#!/system/bin/sh
# service.sh - FKTee-rs late_start service
# Two operating modes (mutually exclusive):
#   1. HAL 模式（/data/adb/Tee-rs/hal.enabled 存在）：
#      post-fs-data.sh 已把真 HAL vintf 实例改为 fktee-real。
#      此处启动 fktee-hal 抢注 default，keystore2 路由到我们。
#      inject 路径不启动（避免双 hook 冲突）。
#   2. inject 模式（默认）：
#      启动 fktee backend + injector（ptrace 注入 keystore2）。
# 两种模式都应用 props.conf / usb.conf 配置，并响应文件触发重启信号。

MODDIR=${0%/*}
TEERS_DIR=/data/adb/Tee-rs
DAEMON="$MODDIR/daemon"
DAEMON_INJECTOR="$MODDIR/daemon-injector"
HAL_BIN="$MODDIR/libs/$(getprop ro.product.cpu.abi)/fktee-hal"
PID_FKTEE="$TEERS_DIR/data/fktee.pid"
PID_INJECTOR="$TEERS_DIR/data/injector.pid"
PID_HAL="$TEERS_DIR/data/hal.pid"
HAL_ENABLED=0
[ -f "$TEERS_DIR/hal.enabled" ] && HAL_ENABLED=1

# ---------- Wait for boot completed ----------
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done
# Give keystore2 a moment to settle
sleep 3

# ---------- Prop hiding (resetprop, config-driven) ----------
# 读取 /data/adb/Tee-rs/props.conf（每行 key=value，# 与空行忽略）。
# 特殊键 enabled=1 开启；其余行先 resetprop --delete 再 resetprop set，
# 保证读取者看不到原始值。无 resetprop 或无配置文件则跳过。
#
# 支持两种行前缀语法：
#   key~match=value    仅当 getprop(key) 包含 match 才覆盖（contains_reset_prop）
#   once:key=value     仅在开机时执行一次，主循环轮询时跳过
#                      （用于 sys.boot_completed=0 等“一次性”条目，
#                       避免每 5s 把它持续压回 0 导致系统误判未开机）
#
# 用法: apply_props [all|once|loop]
#   all  开机时用，处理全部条目（含 once:）— 缺省
#   once 仅处理 once: 前缀条目
#   loop 仅处理非 once: 前缀条目（主循环轮询用）
apply_props() {
    local conf="$TEERS_DIR/props.conf"
    [ -f "$conf" ] || return 0
    command -v resetprop >/dev/null 2>&1 || return 0
    local mode="${1:-all}"

    local enabled=1
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue;; esac
        [ "${line%%=*}" = "enabled" ] && { enabled=${line#*=}; break; }
    done < "$conf"
    [ "$enabled" = "1" ] || return 0

    local spec key val match cur is_once
    while IFS= read -r line; do
        case "$line" in ''|\#*|enabled=*) continue;; esac
        spec=${line%%=*}; val=${line#*=}
        is_once=0
        case "$spec" in
            once:*) is_once=1; spec=${spec#once:};;
        esac
        # 按模式过滤：once 模式只跑 once 条目；loop 模式只跑非 once 条目
        case "$mode:$is_once" in
            once:0) continue;;
            loop:1) continue;;
        esac
        # ~ 条件语法：仅当 getprop(key) 含 match 才覆盖
        case "$spec" in
            *~*)
                key=${spec%%~*}; match=${spec#*~}
                cur=$(getprop "$key" 2>/dev/null)
                case "$cur" in
                    *"$match"*)
                        resetprop --delete "$key" 2>/dev/null
                        resetprop "$key" "$val" 2>/dev/null
                        ;;
                esac
                ;;
            *)
                resetprop --delete "$spec" 2>/dev/null
                resetprop "$spec" "$val" 2>/dev/null
                ;;
        esac
    done < "$conf"
}

# ---------- USB 调试开关 (config-driven) ----------
# 读取 /data/adb/Tee-rs/usb.conf 的 adb_enabled=1/0，通过 settings 持久化。
apply_usb() {
    local conf="$TEERS_DIR/usb.conf"
    [ -f "$conf" ] || return 0
    local adb=1
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue;; esac
        [ "${line%%=*}" = "adb_enabled" ] && { adb=${line#*=}; break; }
    done < "$conf"
    # settings 在 late_start 阶段已可用
    command -v settings >/dev/null 2>&1 && settings put global adb_enabled "$adb" 2>/dev/null
}

apply_props all   # 开机：处理全部条目（含 once: 一次性项）
apply_usb

# ---------- Helpers ----------
is_pid_alive() {
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] && [ -d "/proc/$pid" ]
}

kill_pidfile() {
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
    rm -f "$1"
}

# ---------- HAL 模式：启动 fktee-hal ----------
# 抢注 default 实例。真 HAL 已被 post-fs-data 改名为 fktee-real，
# fktee-hal 启动后 wait_for_interface 拿真 HAL 代理转发非 attestation 事务。
start_hal() {
    if [ ! -x "$HAL_BIN" ]; then
        echo "[fktee-hal] 二进制不存在: $HAL_BIN" >&2
        return 1
    fi
    # 检查 vintf 是否已重写（post-fs-data 标记）
    if [ ! -f "$TEERS_DIR/data/hal.vintf-rewritten" ]; then
        echo "[fktee-hal] 警告: vintf 未重写，真 HAL 可能仍占用 default 实例"
        echo "[fktee-hal] fktee-hal 抢注 default 会失败。请检查 hal.enabled + vintf manifest"
    fi
    # fktee-hal 内部 wait_for_service 阻塞至真 HAL（fktee-real）上线，
    # 此处无需额外 sleep。nohup 让它脱离 service.sh 主循环独立运行。
    nohup "$HAL_BIN" >"$TEERS_DIR/logs/hal.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_HAL"
    echo "[fktee-hal] started pid=$pid log=$TEERS_DIR/logs/hal.log"
}

# ---------- inject 模式：watchdog 启动 ----------
launch_watchdog() {
    wd="$1"
    if [ -x "$wd" ]; then
        nohup "$wd" >/dev/null 2>&1 &
    fi
}

if [ "$HAL_ENABLED" = "1" ]; then
    echo "[fktee] HAL 模式启用，启动 fktee-hal（inject 路径跳过）"
    start_hal
else
    echo "[fktee] inject 模式（默认），启动 fktee backend + injector"
    launch_watchdog "$DAEMON"
    launch_watchdog "$DAEMON_INJECTOR"
fi

# Give watchdogs/HAL a chance to spawn
sleep 2

# ---------- Main loop: consume restart signals ----------
# restart.all      -> restart all daemons (含 HAL 模式下的 fktee-hal)
# restart.fktee    -> restart fktee backend only (inject 模式)
# restart.injector -> restart injector only (inject 模式)
# restart.hal      -> restart fktee-hal only (HAL 模式)
while true; do
    if [ -f "$TEERS_DIR/restart.all" ]; then
        rm -f "$TEERS_DIR/restart.all"
        kill_pidfile "$PID_FKTEE"
        kill_pidfile "$PID_INJECTOR"
        kill_pidfile "$PID_HAL"
        [ "$HAL_ENABLED" = "1" ] && start_hal || {
            launch_watchdog "$DAEMON"
            launch_watchdog "$DAEMON_INJECTOR"
        }
    fi

    if [ -f "$TEERS_DIR/restart.fktee" ]; then
        rm -f "$TEERS_DIR/restart.fktee"
        kill_pidfile "$PID_FKTEE"
        [ "$HAL_ENABLED" != "1" ] && launch_watchdog "$DAEMON"
    fi

    if [ -f "$TEERS_DIR/restart.injector" ]; then
        rm -f "$TEERS_DIR/restart.injector"
        kill_pidfile "$PID_INJECTOR"
        [ "$HAL_ENABLED" != "1" ] && launch_watchdog "$DAEMON_INJECTOR"
    fi

    if [ -f "$TEERS_DIR/restart.hal" ]; then
        rm -f "$TEERS_DIR/restart.hal"
        kill_pidfile "$PID_HAL"
        [ "$HAL_ENABLED" = "1" ] && start_hal
    fi

    # Re-apply prop hiding & USB state periodically (some processes reset props)
    # loop 模式跳过 once: 条目，避免 sys.boot_completed 被持续压回 0
    apply_props loop
    apply_usb

    sleep 5
done

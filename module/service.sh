#!/system/bin/sh
# service.sh - FKTee-rs late_start service
# Starts the two daemons (fktee backend + injector) and keeps them alive
# via the watchdog scripts. Also applies prop hiding and reacts to
# file-based restart signals:  touch /data/adb/Tee-rs/restart.{fktee,injector,all}
#
# 注：当前实现走 ptrace 注入路径（inject + inject_payload）。KeyMint HAL 替换
# 路径（crates/hal，方案 A）尚为骨架，未接进启动——它需要完整 KeyMint AIDL
# 实现才能不瘫痪 keystore2。HAL 成熟后此脚本改为启动 fktee-hal service。

MODDIR=${0%/*}
TEERS_DIR=/data/adb/Tee-rs
DAEMON="$MODDIR/daemon"
DAEMON_INJECTOR="$MODDIR/daemon-injector"
PID_FKTEE="$TEERS_DIR/data/fktee.pid"
PID_INJECTOR="$TEERS_DIR/data/injector.pid"

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

# ---------- Launch watchdogs (they own the real daemons) ----------
launch_watchdog() {
    wd="$1"
    if [ -x "$wd" ]; then
        nohup "$wd" >/dev/null 2>&1 &
    fi
}

launch_watchdog "$DAEMON"
launch_watchdog "$DAEMON_INJECTOR"

# Give watchdogs a chance to spawn their children
sleep 2

# ---------- Main loop: consume restart signals ----------
# restart.all      -> restart both daemons
# restart.fktee    -> restart fktee backend only
# restart.injector -> restart injector only
while true; do
    # restart.all: kill both, watchdogs will respawn them
    if [ -f "$TEERS_DIR/restart.all" ]; then
        rm -f "$TEERS_DIR/restart.all"
        kill_pidfile "$PID_FKTEE"
        kill_pidfile "$PID_INJECTOR"
    fi

    if [ -f "$TEERS_DIR/restart.fktee" ]; then
        rm -f "$TEERS_DIR/restart.fktee"
        kill_pidfile "$PID_FKTEE"
    fi

    if [ -f "$TEERS_DIR/restart.injector" ]; then
        rm -f "$TEERS_DIR/restart.injector"
        kill_pidfile "$PID_INJECTOR"
    fi

    # Re-apply prop hiding & USB state periodically (some processes reset props)
    # loop 模式跳过 once: 条目，避免 sys.boot_completed 被持续压回 0
    apply_props loop
    apply_usb

    sleep 5
done

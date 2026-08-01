#!/system/bin/sh
# service.sh - FKTee-rs late_start service
# Starts the two daemons (fktee backend + injector) and keeps them alive
# via the watchdog scripts. Also applies prop hiding and reacts to
# file-based restart signals:  touch /data/adb/fktee/restart.{fktee,injector,all}

MODDIR=${0%/*}
FKTEE_DIR=/data/adb/fktee
DAEMON="$MODDIR/daemon"
DAEMON_INJECTOR="$MODDIR/daemon-injector"
PID_FKTEE="$FKTEE_DIR/data/fktee.pid"
PID_INJECTOR="$FKTEE_DIR/data/injector.pid"

# ---------- Wait for boot completed ----------
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done
# Give keystore2 a moment to settle
sleep 3

# ---------- Prop hiding (resetprop, config-driven) ----------
# 读取 /data/adb/fktee/props.conf（每行 key=value，# 与空行忽略）。
# 特殊键 enabled=1 开启；其余行先 resetprop --delete 再 resetprop set，
# 保证读取者看不到原始值。无 resetprop 或无配置文件则跳过。
# 支持条件语法 key~match=value：仅当 getprop(key) 包含 match 才覆盖
# （对应 contains_reset_prop，避免把正常值误改，如 bootmode=normal）。
apply_props() {
    local conf="$FKTEE_DIR/props.conf"
    [ -f "$conf" ] || return 0
    command -v resetprop >/dev/null 2>&1 || return 0

    local enabled=1
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue;; esac
        [ "${line%%=*}" = "enabled" ] && { enabled=${line#*=}; break; }
    done < "$conf"
    [ "$enabled" = "1" ] || return 0

    local spec key val match cur
    while IFS= read -r line; do
        case "$line" in ''|\#*|enabled=*) continue;; esac
        spec=${line%%=*}; val=${line#*=}
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
# 读取 /data/adb/fktee/usb.conf 的 adb_enabled=1/0，通过 settings 持久化。
apply_usb() {
    local conf="$FKTEE_DIR/usb.conf"
    [ -f "$conf" ] || return 0
    local adb=1
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue;; esac
        [ "${line%%=*}" = "adb_enabled" ] && { adb=${line#*=}; break; }
    done < "$conf"
    # settings 在 late_start 阶段已可用
    command -v settings >/dev/null 2>&1 && settings put global adb_enabled "$adb" 2>/dev/null
}

apply_props
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
    if [ -f "$FKTEE_DIR/restart.all" ]; then
        rm -f "$FKTEE_DIR/restart.all"
        kill_pidfile "$PID_FKTEE"
        kill_pidfile "$PID_INJECTOR"
    fi

    if [ -f "$FKTEE_DIR/restart.fktee" ]; then
        rm -f "$FKTEE_DIR/restart.fktee"
        kill_pidfile "$PID_FKTEE"
    fi

    if [ -f "$FKTEE_DIR/restart.injector" ]; then
        rm -f "$FKTEE_DIR/restart.injector"
        kill_pidfile "$PID_INJECTOR"
    fi

    # Re-apply prop hiding & USB state periodically (some processes reset props)
    apply_props
    apply_usb

    sleep 5
done

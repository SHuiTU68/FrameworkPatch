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

# ---------- Prop hiding (resetprop) ----------
hide_props() {
    command -v resetprop >/dev/null 2>&1 || return 0
    # Delete first so reads don't see the original value
    resetprop --delete ro.boot.verifiedbootstate 2>/dev/null
    resetprop --delete ro.boot.flash.locked 2>/dev/null
    resetprop --delete ro.boot.vbmeta.device_state 2>/dev/null
    resetprop --delete ro.boot.veritymode 2>/dev/null
    # Inject "green/locked" state
    resetprop ro.boot.verifiedbootstate green 2>/dev/null
    resetprop ro.boot.flash.locked 1 2>/dev/null
    resetprop ro.boot.vbmeta.device_state locked 2>/dev/null
    resetprop ro.boot.veritymode enforcing 2>/dev/null
}

hide_props

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

    # Re-apply prop hiding periodically (some processes reset props)
    hide_props

    sleep 5
done

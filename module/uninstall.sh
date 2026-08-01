#!/system/bin/sh
# uninstall.sh - FKTee-rs cleanup on module removal

TEERS_DIR=/data/adb/Tee-rs
KEYSTORE_DIR=/data/misc/keystore/fktee

# Stop daemons if still running
for pidfile in "$TEERS_DIR/data/fktee.pid" "$TEERS_DIR/data/injector.pid"; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        rm -f "$pidfile"
    fi
done

# Remove runtime data directory
rm -rf "$TEERS_DIR"

# Remove keystore integration data
rm -rf "$KEYSTORE_DIR"

# Remove any stray restart markers
rm -f /data/adb/Tee-rs/restart.* 2>/dev/null

exit 0

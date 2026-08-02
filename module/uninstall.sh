#!/system/bin/sh
# uninstall.sh - FKTee-rs cleanup on module removal

TEERS_DIR=/data/adb/Tee-rs
KEYSTORE_DIR=/data/misc/keystore/fktee

# Stop daemons if still running
for pidfile in "$TEERS_DIR/data/fktee.pid" "$TEERS_DIR/data/injector.pid" "$TEERS_DIR/data/hal.pid"; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        rm -f "$pidfile"
    fi
done

# Restore VINTF manifests from .fktee-bak backups (HAL 模式遗留)
# post-fs-data.sh 重写 vintf 时备份到 .fktee-bak，卸载时恢复原实例名。
for f in /vendor/etc/vintf/manifest.xml /vendor/etc/vintf/manifest/*.xml \
         /odm/etc/vintf/manifest.xml /odm/etc/vintf/manifest/*.xml; do
    [ -f "$f.fktee-bak" ] || continue
    mv -f "$f.fktee-bak" "$f"
    echo "[fktee] restored vintf: $f"
done

# Remove runtime data directory
rm -rf "$TEERS_DIR"

# Remove keystore integration data
rm -rf "$KEYSTORE_DIR"

# Remove any stray restart markers
rm -f /data/adb/Tee-rs/restart.* 2>/dev/null

exit 0

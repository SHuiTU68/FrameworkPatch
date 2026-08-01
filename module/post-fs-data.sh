#!/system/bin/sh
# post-fs-data.sh - FKTee-rs early boot setup
# Runs early, before most daemons. Keep it fast and side-effect free.

MODDIR=${0%/*}
FKTEE_DIR=/data/adb/fktee

# ---------- Ensure directory structure ----------
# 配置放在 $FKTEE_DIR 根目录（与 daemon/injector 硬编码路径一致）。
mkdir -p "$FKTEE_DIR" "$FKTEE_DIR/data" "$FKTEE_DIR/logs"
chmod 0700 "$FKTEE_DIR" "$FKTEE_DIR/data" "$FKTEE_DIR/logs" 2>/dev/null

# ---------- Copy default configs (never overwrite existing) ----------
# copy_default <module_src> <fktee_dst>
copy_default() {
    src="$MODDIR/$1"
    dst="$FKTEE_DIR/$2"
    [ -f "$src" ] || return 1
    if [ ! -f "$dst" ]; then
        cp -f "$src" "$dst"
        chmod 0600 "$dst"
    fi
    return 0
}

copy_default config.toml    config.toml
copy_default injector.toml  injector.toml
copy_default keybox.xml     keybox.xml
copy_default deny.list      deny.list
copy_default props.conf     props.conf
copy_default usb.conf       usb.conf

# ---------- Clean stale runtime artifacts ----------
# Old pid files from previous boot (process gone after reboot)
rm -f "$FKTEE_DIR/data/fktee.pid" \
      "$FKTEE_DIR/data/injector.pid"

# Stale restart markers (no daemon is running yet to consume them)
rm -f "$FKTEE_DIR/restart.fktee" \
      "$FKTEE_DIR/restart.injector" \
      "$FKTEE_DIR/restart.all"

# Rotate oversized logs (keep last run only)
for log in "$FKTEE_DIR/logs"/*.log; do
    [ -f "$log" ] || continue
    size=$(wc -c < "$log" 2>/dev/null || echo 0)
    if [ "$size" -gt 1048576 ]; then
        mv -f "$log" "$log.old"
    fi
done

exit 0

#!/system/bin/sh
# post-fs-data.sh - FKTee-rs early boot setup
# Runs early, before most daemons. Keep it fast and side-effect free.

MODDIR=${0%/*}
FKTEE_DIR=/data/adb/fktee

# ---------- Ensure directory structure ----------
mkdir -p "$FKTEE_DIR/config" "$FKTEE_DIR/data" "$FKTEE_DIR/logs"
chmod 0700 "$FKTEE_DIR" "$FKTEE_DIR/config" "$FKTEE_DIR/data" "$FKTEE_DIR/logs" 2>/dev/null

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

copy_default config.toml    config/config.toml
copy_default injector.toml  config/injector.toml
copy_default keybox.xml     config/keybox.xml

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

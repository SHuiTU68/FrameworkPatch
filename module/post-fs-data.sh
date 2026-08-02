#!/system/bin/sh
# post-fs-data.sh - FKTee-rs early boot setup
# 参考 OMK：早期启动只做目录/权限/配置准备，不做 mount / vintf 重写。
# vintf 重写挪到 service.sh（late_start 阶段 SELinux 已就绪）。
# 此阶段保持快速、副作用最小，避免 bootloop。

MODDIR=${0%/*}
TEERS_DIR=/data/adb/Tee-rs

# ---------- Ensure directory structure ----------
mkdir -p "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs"
chmod 0700 "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs" 2>/dev/null

# ---------- Copy default configs (never overwrite existing) ----------
copy_default() {
  src="$MODDIR/$1"
  dst="$TEERS_DIR/$2"
  [ -f "$src" ] || return 0
  if [ ! -f "$dst" ]; then
    cp -f "$src" "$dst"
    chmod 0600 "$dst"
  fi
  return 0
}

copy_default config.toml    config.toml
copy_default injector.toml  injector.toml
copy_default hal.toml       hal.toml
copy_default deny.list      deny.list
copy_default props.conf     props.conf
copy_default usb.conf       usb.conf
# keybox.xml: 只在用户没有时复制模块自带占位
if [ ! -f "$TEERS_DIR/keybox.xml" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp -f "$MODDIR/keybox.xml" "$TEERS_DIR/keybox.xml"
  chmod 0600 "$TEERS_DIR/keybox.xml"
fi

# ---------- Clean stale runtime artifacts ----------
rm -f "$TEERS_DIR/data/fktee.pid" \
      "$TEERS_DIR/data/injector.pid" \
      "$TEERS_DIR/data/hal.pid"
rm -f "$TEERS_DIR/restart.fktee" \
      "$TEERS_DIR/restart.injector" \
      "$TEERS_DIR/restart.hal" \
      "$TEERS_DIR/restart.all"
rm -f "$TEERS_DIR/data/hal.vintf-rewritten"

# ---------- Rotate oversized logs ----------
for log in "$TEERS_DIR/logs"/*.log; do
  [ -f "$log" ] || continue
  size=$(wc -c < "$log" 2>/dev/null || echo 0)
  if [ "$size" -gt 1048576 ]; then
    mv -f "$log" "$log.old"
  fi
done

exit 0

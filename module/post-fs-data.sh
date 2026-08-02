#!/system/bin/sh
# post-fs-data.sh - FKTee-rs early boot setup
# Runs early, before most daemons. Keep it fast and side-effect free.

MODDIR=${0%/*}
TEERS_DIR=/data/adb/Tee-rs

# ---------- Ensure directory structure ----------
# 配置放在 $TEERS_DIR 根目录（与 daemon/injector 硬编码路径一致）。
mkdir -p "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs"
chmod 0700 "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs" 2>/dev/null

# ---------- Copy default configs (never overwrite existing) ----------
# copy_default <module_src> <fktee_dst>
copy_default() {
    src="$MODDIR/$1"
    dst="$TEERS_DIR/$2"
    [ -f "$src" ] || return 1
    if [ ! -f "$dst" ]; then
        cp -f "$src" "$dst"
        chmod 0600 "$dst"
    fi
    return 0
}

copy_default config.toml    config.toml
copy_default injector.toml  injector.toml
copy_default hal.toml       hal.toml
copy_default keybox.xml     keybox.xml
copy_default deny.list      deny.list
copy_default props.conf     props.conf
copy_default usb.conf       usb.conf

# ---------- Clean stale runtime artifacts ----------
# Old pid files from previous boot (process gone after reboot)
rm -f "$TEERS_DIR/data/fktee.pid" \
      "$TEERS_DIR/data/injector.pid" \
      "$TEERS_DIR/data/hal.pid"

# Stale restart markers (no daemon is running yet to consume them)
rm -f "$TEERS_DIR/restart.fktee" \
      "$TEERS_DIR/restart.injector" \
      "$TEERS_DIR/restart.all"

# Rotate oversized logs (keep last run only)
for log in "$TEERS_DIR/logs"/*.log; do
    [ -f "$log" ] || continue
    size=$(wc -c < "$log" 2>/dev/null || echo 0)
    if [ "$size" -gt 1048576 ]; then
        mv -f "$log" "$log.old"
    fi
done

# ---------- HAL 模式：重写真 HAL vintf 实例名 ----------
# 仅当 /data/adb/Tee-rs/hal.enabled 存在时执行。把真 HAL 的 default 实例
# 改名为 fktee-real，让 fktee-hal 能抢注 default 被 keystore2 路由。
#
# vintf manifest 路径因 vendor 而异，常见位置：
#   /vendor/etc/vintf/manifest.xml
#   /vendor/etc/vintf/manifest/*.xml
#   /odm/etc/vintf/manifest.xml
#   /odm/etc/vintf/manifest/*.xml
#   /system/etc/vintf/manifest/*.xml (framework manifest, 一般不动)
# 扫 vendor + odm 段，避免误改 framework manifest。
#
# 替换规则：IKeyMintDevice/<old> → IKeyMintDevice/fktee-real
# <old> 通常是 default / strongbox / keymint-service.*，全部改名。
# 同时处理 <fqname> 与 <instance> 标签内的实例名。
#
# 备份原文件到 .fktee-bak，uninstall.sh 据此恢复。
rewrite_vintf_for_hal() {
    [ -f "$TEERS_DIR/hal.enabled" ] || return 0
    local real_instance="fktee-real"
    local changed=0
    local f
    # 收集所有 vendor / odm vintf manifest
    local manifests=""
    for d in /vendor/etc/vintf /odm/etc/vintf; do
        [ -d "$d" ] || continue
        # 顶层 manifest.xml
        [ -f "$d/manifest.xml" ] && manifests="$manifests $d/manifest.xml"
        # manifest/ 子目录下的分片
        if [ -d "$d/manifest" ]; then
            for f in "$d"/manifest/*.xml; do
                [ -f "$f" ] && manifests="$manifests $f"
            done
        fi
    done

    for f in $manifests; do
        # 只处理含 keymint 声明的文件
        grep -q "android.hardware.security.keymint" "$f" 2>/dev/null || continue
        # 备份（仅首次）
        [ -f "$f.fktee-bak" ] || cp -f "$f" "$f.fktee-bak"
        # sed 替换 IKeyMintDevice/<任意> → IKeyMintDevice/fktee-real
        # 用临时文件避免 in-place 兼容性问题
        local tmp="$f.fktee-tmp"
        if sed -E "s|IKeyMintDevice/[^<\"[:space:]]+|IKeyMintDevice/${real_instance}|g" "$f" > "$tmp" 2>/dev/null; then
            mv -f "$tmp" "$f"
            changed=1
            echo "[fktee-hal] vintf rewritten: $f"
        else
            rm -f "$tmp"
        fi
    done
    # 标记此次启动已启用 HAL 模式，service.sh 据此启动 fktee-hal
    [ "$changed" = "1" ] && touch "$TEERS_DIR/data/hal.vintf-rewritten"
    if [ "$changed" = "0" ]; then
        echo "[fktee-hal] 警告: hal.enabled 存在但未找到 keymint vintf manifest"
        echo "[fktee-hal] 真机请检查: ls /vendor/etc/vintf/ /odm/etc/vintf/"
    fi
}

rewrite_vintf_for_hal

exit 0

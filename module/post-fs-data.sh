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
# **关键**：vendor/odm 分区在 post-fs-data 阶段为只读，直接 sed+mv 会失败。
# 改用：sed 生成改写副本到 $TEERS_DIR/data/，再 mount --bind 覆盖原文件。
# bind mount 在 post-fs-data 阶段即可生效，且无需 remount vendor。
#
# vintf manifest 路径因 vendor 而异，常见位置：
#   /vendor/etc/vintf/manifest.xml
#   /vendor/etc/vintf/manifest/*.xml
#   /odm/etc/vintf/manifest.xml
#   /odm/etc/vintf/manifest/*.xml
# 扫 vendor + odm 段，避免误改 framework manifest。
#
# 替换规则：IKeyMintDevice/<old> → IKeyMintDevice/fktee-real
# <old> 通常是 default / strongbox / keymint-service.*，全部改名。
# 同时处理 <fqname> 与 <instance> 标签内的实例名。
#
# 卸载时：uninstall.sh 无法 undo bind mount（模块卸载需重启），但重启后
# bind mount 自动消失，原 vendor 文件未变，无需恢复。.fktee-bak 仅作记录。
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

    mkdir -p "$TEERS_DIR/data/vintf-overlay"
    for f in $manifests; do
        # 只处理含 keymint 声明的文件
        grep -q "android.hardware.security.keymint" "$f" 2>/dev/null || continue
        # 备份原文件内容（仅记录，bind mount 不修改原文件）
        [ -f "$f.fktee-bak" ] || cp -f "$f" "$f.fktee-bak" 2>/dev/null
        # sed 生成改写副本到 data 目录（可写）
        local base=$(echo "$f" | tr '/' '_')
        local tmp="$TEERS_DIR/data/vintf-overlay/$base"
        if sed -E "s|IKeyMintDevice/[^<\"[:space:]]+|IKeyMintDevice/${real_instance}|g" "$f" > "$tmp" 2>/dev/null; then
            # bind mount 覆盖原文件（post-fs-data 阶段 vendor 只读，但 bind mount 可行）
            if mount --bind "$tmp" "$f" 2>/dev/null; then
                changed=1
                echo "[fktee-hal] vintf bind-mounted: $f"
            else
                echo "[fktee-hal] bind mount 失败: $f（尝试 remount）"
                # 尝试 remount vendor 可写后再 bind（部分设备需要）
                mount -o rw,remount "$f" 2>/dev/null
                mount --bind "$tmp" "$f" 2>/dev/null && changed=1
            fi
        fi
    done
    # 标记此次启动已启用 HAL 模式，service.sh 据此启动 fktee-hal
    [ "$changed" = "1" ] && touch "$TEERS_DIR/data/hal.vintf-rewritten"
    if [ "$changed" = "0" ]; then
        echo "[fktee-hal] 警告: hal.enabled 存在但 vintf 重写失败"
        echo "[fktee-hal] 真机请检查: ls /vendor/etc/vintf/ /odm/etc/vintf/"
        echo "[fktee-hal] 且确认 mount --bind 可用（需 sepolicy 放行 mountfs）"
    fi
}

rewrite_vintf_for_hal

exit 0

#!/system/bin/sh
# customize.sh - FKTee-rs installation script
# 参考 OMK 安装逻辑：用 verify.sh 的 extract 函数逐个解压+校验，
# 避免 SKIPUNZIP + 全局 unzip 在部分设备上的兼容性问题。

SKIPUNZIP=1

SONAME="FKTee-rs"
SUPPORTED_ABIS="arm64"
MIN_SDK=29

# ---------- Root implementation detection ----------
if [ "$BOOTMODE" ] && [ "$KSU" ]; then
  ui_print "- Installing from KernelSU app"
  ui_print "- KernelSU version: $KSU_KERNEL_VER_CODE (kernel) + $KSU_VER_CODE (ksud)"
  if [ "$(which magisk)" ]; then
    ui_print "*********************************************************"
    ui_print "! Multiple root implementation is NOT supported!"
    ui_print "! Please uninstall Magisk before installing $SONAME"
    abort    "*********************************************************"
  fi
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
  ui_print "- Installing from Magisk app"
else
  ui_print "*********************************************************"
  ui_print "! Install from recovery is not supported"
  ui_print "! Please install from KernelSU or Magisk app"
  abort    "*********************************************************"
fi

VERSION=$(grep_prop version "${TMPDIR}/module.prop")
ui_print "- Installing $SONAME $VERSION"

# ---------- Architecture check ----------
support=false
for abi in $SUPPORTED_ABIS; do
  if [ "$ARCH" == "$abi" ]; then
    support=true
  fi
done
if [ "$support" == "false" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

# ---------- Android version check ----------
if [ "$API" -lt $MIN_SDK ]; then
  ui_print "! Unsupported sdk: $API"
  abort "! Minimal supported sdk is $MIN_SDK"
else
  ui_print "- Device sdk: $API"
fi

# ---------- Extract verify.sh ----------
ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort    "*********************************************************"
fi
. "$TMPDIR/verify.sh"
extract "$ZIPFILE" 'customize.sh'  "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh'     "$TMPDIR/.vunzip"

# ---------- Extract module files (逐个 extract + 校验) ----------
ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'       "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh'   "$MODPATH"
extract "$ZIPFILE" 'service.sh'        "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule'     "$MODPATH"
extract "$ZIPFILE" 'daemon'            "$MODPATH"
extract "$ZIPFILE" 'daemon-injector'   "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh'      "$MODPATH"
extract "$ZIPFILE" 'action.sh'         "$MODPATH"
extract "$ZIPFILE" 'config.toml'       "$MODPATH"
extract "$ZIPFILE" 'injector.toml'     "$MODPATH"
extract "$ZIPFILE" 'hal.toml'          "$MODPATH"
extract "$ZIPFILE" 'allow.list'        "$MODPATH"
extract "$ZIPFILE" 'props.conf'        "$MODPATH"
extract "$ZIPFILE" 'usb.conf'          "$MODPATH"
extract "$ZIPFILE" 'keybox.xml'        "$MODPATH"

chmod 755 "$MODPATH/daemon" "$MODPATH/daemon-injector" \
  "$MODPATH/post-fs-data.sh" "$MODPATH/service.sh" \
  "$MODPATH/uninstall.sh" "$MODPATH/action.sh"

# ---------- Extract binaries by architecture ----------
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "arm64-v8a" ]; then
  ui_print "- Using packaged arm64 binaries"
  BINDIR="$MODPATH/libs/arm64-v8a"
  extract "$ZIPFILE" 'libs/arm64-v8a/fktee'           "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/inject'          "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/injector.payload' "$MODPATH"
  extract "$ZIPFILE" 'libs/arm64-v8a/fktee-hal'       "$MODPATH"
else
  abort "! Unsupported platform: $ARCH (only arm64-v8a is supported)"
fi

[ -f "$BINDIR/fktee" ]             || abort "! Missing $BINDIR/fktee"
[ -f "$BINDIR/inject" ]            || abort "! Missing $BINDIR/inject"
[ -f "$BINDIR/injector.payload" ]  || abort "! Missing $BINDIR/injector.payload"
[ -f "$BINDIR/fktee-hal" ]         || abort "! Missing $BINDIR/fktee-hal"
chmod 755 "$BINDIR/fktee" "$BINDIR/inject" "$BINDIR/injector.payload" "$BINDIR/fktee-hal"

# ---------- WebUI ----------
# SKIPUNZIP=1 时不会自动解压任何文件，必须手动解压 webroot 整个目录。
# 使用通配符递归解压 webroot/ 下的所有文件，保留目录结构。
ui_print "- Extracting WebUI"
WEBUI_EXTRACTED=0
if unzip -o "$ZIPFILE" 'webroot/*' -d "$MODPATH" >/dev/null 2>&1; then
  if [ -d "$MODPATH/webroot" ] && [ -n "$(ls -A "$MODPATH/webroot" 2>/dev/null)" ]; then
    # 移除 unzip 通配符可能产生的空 webroot 条目，保留实际文件
    ui_print "- WebUI bundled ($(ls -1 "$MODPATH/webroot" 2>/dev/null | wc -l) entries)"
    WEBUI_EXTRACTED=1
  fi
fi
if [ "$WEBUI_EXTRACTED" = "0" ]; then
  ui_print "- WebUI not bundled in this zip"
  ui_print "- 提示：构建前需先执行 cd webui && npm ci && npm run build"
fi

# ---------- Config dir setup ----------
CONFIG_DIR=/data/adb/Tee-rs
mkdir -p "$CONFIG_DIR/data" "$CONFIG_DIR/logs"
chmod 0700 "$CONFIG_DIR" "$CONFIG_DIR/data" "$CONFIG_DIR/logs"

# Clean stale runtime artifacts from previous install
rm -f "$CONFIG_DIR/data/fktee.pid" "$CONFIG_DIR/data/injector.pid" "$CONFIG_DIR/data/hal.pid"
rm -f "$CONFIG_DIR/restart.fktee" "$CONFIG_DIR/restart.injector" "$CONFIG_DIR/restart.hal" "$CONFIG_DIR/restart.all"
rm -f "$CONFIG_DIR/data/hal.vintf-rewritten"

# Copy default configs (never overwrite existing user configs)
copy_default() {
  src="$MODPATH/$1"
  dst="$CONFIG_DIR/$2"
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
copy_default allow.list     allow.list
copy_default props.conf     props.conf
copy_default usb.conf       usb.conf
# keybox.xml: 只在用户没有时用模块自带的占位 keybox（用户应替换为真实 keybox）
if [ ! -f "$CONFIG_DIR/keybox.xml" ]; then
  cp -f "$MODPATH/keybox.xml" "$CONFIG_DIR/keybox.xml"
  chmod 0600 "$CONFIG_DIR/keybox.xml"
fi

ui_print "- Installation complete"
ui_print "- Reboot to activate $SONAME"

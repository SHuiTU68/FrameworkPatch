#!/system/bin/sh
# customize.sh - FKTee-rs installation script (Magisk/KSU/APatch)

SKIPUNZIP=1
PROP_SKIP_DELETE=1

# ---------- Helper ----------
ui_print() { echo "ui_print $1" >&1; echo "ui_print" >&1; }

# ---------- Architecture check ----------
ARCH=$(getprop ro.product.cpu.abi)
case "$ARCH" in
    arm64-v8a|x86_64)
        ui_print "- Supported architecture: $ARCH"
        ;;
    *)
        ui_print "! Unsupported architecture: $ARCH"
        abort "! FKTee-rs only supports arm64-v8a and x86_64"
        ;;
esac

# ---------- Android version check ----------
SDK=$(getprop ro.build.version.sdk)
if [ -z "$SDK" ]; then
    SDK=$(getprop ro.build.version.sdk_int)
fi
if [ -z "$SDK" ] || [ "$SDK" -lt 29 ]; then
    ui_print "! Unsupported Android SDK: ${SDK:-unknown}"
    abort "! FKTee-rs requires Android 10+ (SDK 29)"
fi
ui_print "- Android SDK: $SDK"

# ---------- Extract module files ----------
ui_print "- Extracting module files..."
unzip -o "$ZIPFILE" -x 'META-INF/*' -d "$MODPATH" >/dev/null 2>&1

# ---------- Select binaries by architecture ----------
ui_print "- Installing binaries for $ARCH..."
if [ -d "$MODPATH/libs/$ARCH" ]; then
    for bin in "$MODPATH/libs/$ARCH"/*; do
        [ -f "$bin" ] && chmod 0755 "$bin"
    done
else
    abort "! No binaries found for $ARCH in libs/$ARCH"
fi

# ---------- Create config directory ----------
TEERS_DIR=/data/adb/Tee-rs
ui_print "- Creating config directory: $TEERS_DIR"
# 配置直接放在 $TEERS_DIR 根目录（与 daemon/injector 读取的硬编码路径一致），
# data/ 与 logs/ 仍为子目录。避免 config/ 子目录导致的路径不一致。
mkdir -p "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs"
chmod 0700 "$TEERS_DIR" "$TEERS_DIR/data" "$TEERS_DIR/logs"

# ---------- Copy default configs on first install ----------
# copy_default <module_src> <fktee_dst>
copy_default() {
    src="$MODPATH/$1"
    dst="$TEERS_DIR/$2"
    if [ ! -f "$src" ]; then
        ui_print "! Missing template: $1"
        return 1
    fi
    if [ -f "$dst" ]; then
        ui_print "- Kept existing: $2"
    else
        cp -f "$src" "$dst"
        chmod 0600 "$dst"
        ui_print "- Installed default: $2"
    fi
    return 0
}

copy_default config.toml    config.toml
copy_default injector.toml  injector.toml
copy_default keybox.xml     keybox.xml
copy_default deny.list      deny.list
copy_default props.conf     props.conf
copy_default usb.conf       usb.conf

# ---------- Set permissions ----------
ui_print "- Setting permissions..."
set_perm_recursive "$MODPATH" 0 0 0755 0755
set_perm_recursive "$MODPATH/libs" 0 0 0755 0755
set_perm "$MODPATH/service.sh"        0 0 0700
set_perm "$MODPATH/post-fs-data.sh"   0 0 0700
set_perm "$MODPATH/uninstall.sh"      0 0 0700
set_perm "$MODPATH/action.sh"         0 0 0700
set_perm "$MODPATH/daemon"            0 0 0700
set_perm "$MODPATH/daemon-injector"   0 0 0700

# Mark binaries executable
for bin in "$MODPATH/libs/$ARCH"/*; do
    [ -f "$bin" ] && set_perm "$bin" 0 0 0755
done

ui_print "- Installation complete"
ui_print "- Reboot to activate FKTee-rs"

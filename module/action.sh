#!/system/bin/sh
# KSU/Magisk Action 按钮：启动 WebUI
MODDIR=${0%/*}
if [ -f "$MODDIR/webroot/index.html" ]; then
    echo "WebUI available at /data/adb/modules/fktee_rs/webroot/"
fi

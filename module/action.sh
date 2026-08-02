#!/system/bin/sh
# KSU/Magisk Action 按钮：启动 WebUI
MODDIR=${0%/*}
if [ -f "$MODDIR/webroot/index.html" ]; then
    echo "WebUI available at $MODDIR/webroot/"
    echo "请打开 KernelSU/Magisk 管理器查看模块 WebUI"
fi
#!/system/bin/sh
# ============================================================================
#  手机端脚本：从 /system/framework/framework.jar 提取所有 classes*.dex
#
#  为什么需要这个：
#    GitHub 网页上传单文件限 25MB，framework.jar 通常 100MB+ 上传不了。
#    但单个 dex 文件通常 < 25MB，可以分别上传。
#    CI 端会自动反编译这些 dex，定位三个 hook 点。
#
#  用法（手机 Termux 或 adb shell，需 root）：
#     su -c "sh /sdcard/extract_dex_on_device.sh"
#
#  产物：
#     /sdcard/device_input/classes.dex
#     /sdcard/device_input/classes2.dex
#     /sdcard/device_input/classes3.dex
#     ...
#     /sdcard/device_input/device_info.txt   （顺便采集的设备信息）
#
#  下一步：
#     把 /sdcard/device_input/ 下所有文件上传到 GitHub 仓库的 device_input/ 目录
#     （用手机浏览器在 GitHub 网页点 Add file → Upload files）
# ============================================================================
set -e

SRC="${1:-/system/framework/framework.jar}"
OUT="/sdcard/device_input"

echo "=========================================="
echo "  FrameworkPatch dex 提取脚本（手机端）"
echo "=========================================="
echo "源: $SRC"
echo "输出: $OUT"
echo ""

# ---------- root 检查 ----------
if [ "$(id -u)" != "0" ]; then
    echo "[ERR] 需要 root，请用 su -c 执行"
    echo "  su -c \"sh $0\""
    exit 1
fi
echo "[OK] 已 root"

# ---------- 源文件检查 ----------
if [ ! -f "$SRC" ]; then
    echo "[ERR] 未找到 $SRC"
    exit 1
fi
SRC_SIZE=$(stat -c %s "$SRC" 2>/dev/null || wc -c < "$SRC")
echo "[OK] framework.jar 大小: $SRC_SIZE 字节"

# ---------- 准备输出目录 ----------
rm -rf "$OUT"
mkdir -p "$OUT"

# ---------- 选择 unzip ----------
# Android 10+ 自带 toybox（含 unzip），否则尝试 Termux 的 unzip
UNZIP=""
if command -v unzip >/dev/null 2>&1; then
    UNZIP=unzip
elif command -v toybox >/dev/null 2>&1 && toybox --list 2>/dev/null | grep -q '^unzip$'; then
    UNZIP="toybox unzip"
else
    echo "[ERR] 未找到 unzip"
    echo ""
    echo "解决方案（任选其一）："
    echo "  1. 装 Termux: pkg install unzip"
    echo "  2. 用 MT 管理器/X-plore 等文件管理器手动解压 framework.jar，"
    echo "     把所有 classes*.dex 复制到 /sdcard/device_input/"
    exit 1
fi
echo "[OK] unzip: $UNZIP"

# ---------- 列出 framework.jar 内的 dex ----------
echo ""
echo "=== framework.jar 内的 dex 文件 ==="
$UNZIP -l "$SRC" 2>/dev/null | grep -oE 'classes[0-9]*\.dex' | sort -u

# ---------- 提取所有 dex ----------
echo ""
echo "=== 提取 dex 到 $OUT ==="
# -j: 不保留目录结构（junk paths）
# -o: 覆盖已存在文件
$UNZIP -j -o "$SRC" 'classes*.dex' -d "$OUT"

# ---------- 顺便采集设备信息（供 CI 报告使用） ----------
echo ""
echo "=== 采集设备信息 ==="
INFO="$OUT/device_info.txt"
{
    echo "# 设备信息，由 extract_dex_on_device.sh 采集于 $(date)"
    echo "ro.product.model=$(getprop ro.product.model)"
    echo "ro.product.brand=$(getprop ro.product.brand)"
    echo "ro.product.device=$(getprop ro.product.device)"
    echo "ro.product.manufacturer=$(getprop ro.product.manufacturer)"
    echo "ro.build.version.release=$(getprop ro.build.version.release)"
    echo "ro.build.version.sdk=$(getprop ro.build.version.sdk)"
    echo "ro.build.version.security_patch=$(getprop ro.build.version.security_patch)"
    echo "ro.build.version.incremental=$(getprop ro.build.version.incremental)"
    echo "ro.build.id=$(getprop ro.build.id)"
    echo "ro.build.fingerprint=$(getprop ro.build.fingerprint)"
    echo "ro.build.type=$(getprop ro.build.type)"
    echo "ro.build.tags=$(getprop ro.build.tags)"
    echo "ro.boot.verifiedbootstate=$(getprop ro.boot.verifiedbootstate)"
    echo "ro.boot.flash.locked=$(getprop ro.boot.flash.locked)"
    echo "ro.boot.vbmeta.device_state=$(getprop ro.boot.vbmeta.device_state)"
} > "$INFO"
echo "[OK] 设备信息已写入 $INFO"

# ---------- 结果展示 ----------
echo ""
echo "=========================================="
echo "  提取完成！文件列表："
echo "=========================================="
ls -la "$OUT"/

# ---------- 检查每个 dex 是否超 25MB ----------
echo ""
echo "=== GitHub 上传限制检查（单文件 25MB）==="
OVER=0
for f in "$OUT"/classes*.dex; do
    [ -f "$f" ] || continue
    SIZE=$(stat -c %s "$f" 2>/dev/null || wc -c < "$f")
    NAME=$(basename "$f")
    if [ "$SIZE" -gt 26214400 ]; then
        echo "[WARN] $NAME = $SIZE 字节（> 25MB，网页上传可能失败）"
        OVER=1
    else
        echo "[OK]   $NAME = $SIZE 字节（< 25MB，可网页上传）"
    fi
done

if [ "$OVER" = "1" ]; then
    echo ""
    echo "[WARN] 有 dex 超过 25MB，可选方案："
    echo "  1. 用 Termux git push（单文件限 100MB，需 git 配置 token）"
    echo "  2. 用 split 分片：split -b 20M classesN.dex classesN.dex.part_"
    echo "     （CI 端目前未支持分片合并，需联系上游扩展）"
    echo "  3. 只上传含目标类的 dex（见下方说明）"
fi

echo ""
echo "=========================================="
echo "  下一步操作"
echo "=========================================="
echo ""
echo "1. 把 $OUT/ 下所有文件上传到 GitHub 仓库 device_input/ 目录"
echo "   手机浏览器打开: https://github.com/SHuiTU68/FrameworkPatch"
echo "   进入 device_input/ → Add file → Upload files"
echo ""
echo "2. 上传后 CI 会自动触发，反编译 dex 并生成 report/ADAPT_REPORT.md"
echo ""
echo "3. 完成后在仓库 report/ADAPT_REPORT.md 查看适配报告"
echo "   或在 Actions 页面查看运行日志"
echo ""

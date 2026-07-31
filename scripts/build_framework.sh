#!/usr/bin/env bash
# ============================================================================
# build_framework.sh — 在 CI 上构建 patched framework.jar
#
# 流程:
#   1. 构建 baksmali + smali fat jar（从 google/smali 源码）
#   2. baksmali 反编译 classes.dex 和 classes3.dex
#   3. python3 patch_smali.py 注入 5 个 hook 点
#   4. smali a 重新打包成 dex
#   5. 组装新 framework.jar:
#      - 用 patched dex 替换 classes.dex / classes3.dex
#      - FrameworkPatch 的 dex 作为 classes7.dex（下一个编号）
#      - 其余 dex 原样保留
#   6. zipalign
#   7. 打包 Magisk 模块 zip（可选，便于手机直接刷入）
#
# 用法（CI 内调用）:
#   bash scripts/build_framework.sh
#
# 期望的目录结构（由 extract_smali.sh 准备）:
#   $WORK/framework/           — 原始 dex 文件（classes.dex ~ classes6.dex）
#   $WORK/baksmali.jar         — 反编译器
#   $WORK/smali.jar            — 汇编器
#   app/build/outputs/apk/release/app-release.apk — FrameworkPatch APK
# ============================================================================
set -euo pipefail

# 颜色
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
info() { echo -e "${B}[INFO]${N} $*"; }
ok()   { echo -e "${G}[OK]${N}   $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
err()  { echo -e "${R}[ERR]${N}  $*" >&2; }
die()  { err "$*"; exit 1; }

step() { echo ""; echo -e "${B}========== $* ==========${N}"; }

# ============================================================================
# 0. 路径与参数
# ============================================================================
# 注意：WORK 必须与 extract_smali.sh 一致（fw_work），复用其反编译产物
ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
WORK="${WORK:-fw_work}"
FW_DIR="$WORK/framework"
PATCHED_OUT="$WORK/patched_framework"
MAGISK_OUT="$WORK/magisk_module"
API_LEVEL="${API_LEVEL:-36}"   # Android 16 = 36, 默认从设备信息推断

# FrameworkPatch APK 路径（由 gradlew 构建产出）
FP_APK="$ROOT/app/build/outputs/apk/release/app-release.apk"

# baksmali/smali jar：优先复用 extract_smali.sh 已构建的（在 $ROOT 下），
# 否则自己构建
BAKSMALI_JAR="$ROOT/baksmali.jar"
SMALI_JAR="$ROOT/smali.jar"
SMALI_SRC="/tmp/smali"

mkdir -p "$WORK" "$PATCHED_OUT"

# ============================================================================
step "1. 构建 baksmali + smali fat jar"
# ============================================================================
build_fat_jar() {
    local module="$1" out="$2" name="$3"
    if [ -f "$out" ]; then
        ok "$name 已存在，跳过构建"
        return
    fi
    info "构建 $name (:${module}:fatJar)..."
    if [ ! -d "$SMALI_SRC" ]; then
        git clone --depth=1 https://github.com/google/smali.git "$SMALI_SRC"
    fi
    (
        cd "$SMALI_SRC"
        export GRADLE_USER_HOME=/tmp/smali-gradle
        ./gradlew ":${module}:fatJar" --no-daemon --console=plain 2>&1 | tail -15
    )
    local fat
    fat=$(find "$SMALI_SRC/$module/build/libs" -maxdepth 1 -type f \
          \( -name "${module}-*-fat.jar" -o -name "${module}-fat.jar" \) 2>/dev/null | head -1)
    [ -n "$fat" ] || die "未找到 $name fat jar"
    cp -f "$fat" "$out"
    ok "$name: $out ($(du -h "$out" | cut -f1))"
}

build_fat_jar baksmali "$BAKSMALI_JAR" "baksmali"
build_fat_jar smali    "$SMALI_JAR"    "smali"

# ============================================================================
step "2. 确定需要 patch 的 dex"
# ============================================================================
# Instrumentation      → classes.dex
# AndroidKeyStoreSpi   → classes3.dex
# SystemProperties     → classes3.dex
DEX_TO_PATCH="classes.dex classes3.dex"
info "需要 patch 的 dex: $DEX_TO_PATCH"

for d in $DEX_TO_PATCH; do
    [ -f "$FW_DIR/$d" ] || die "缺少 $FW_DIR/$d"
done

# ============================================================================
step "3. baksmali 反编译 classes.dex 和 classes3.dex（复用 extract_smali.sh 产物）"
# ============================================================================
# extract_smali.sh 已反编译到 $WORK/smali_classes 和 $WORK/smali_classes3
# 这里检查是否存在，缺失才补反编译（保证可独立运行）
for d in $DEX_TO_PATCH; do
    out_dir="$WORK/smali_${d%.dex}"
    if [ -d "$out_dir" ] && [ -n "$(find "$out_dir" -name '*.smali' 2>/dev/null | head -1)" ]; then
        ok "$d 已反编译（复用 extract_smali.sh 产物: $out_dir, $(find "$out_dir" -name '*.smali' | wc -l) 个 smali）"
        continue
    fi
    rm -rf "$out_dir"
    info "baksmali d $d -> $out_dir"
    java -jar "$BAKSMALI_JAR" d "$FW_DIR/$d" -o "$out_dir" 2>"$WORK/baksmali_${d%.dex}.err" \
        || die "baksmali 反编译 $d 失败: $(head -3 "$WORK/baksmali_${d%.dex}.err")"
    ok "$d 反编译完成 ($(find "$out_dir" -name '*.smali' | wc -l) 个 smali)"
done

# ============================================================================
step "4. 注入 FrameworkPatch hook（patch_smali.py）"
# ============================================================================
info "运行 patch_smali.py..."
python3 "$ROOT/scripts/patch_smali.py" \
    "$WORK/smali_classes" "$WORK/smali_classes3" \
    || die "patch 失败，smali 锚点未匹配（检查 smali 结构是否变化）"
ok "5 个 hook 点注入完成"

# ============================================================================
step "5. smali a 重新打包成 dex"
# ============================================================================
# smali 2.5.2 的 mapApiToDexVersion 只到 API 35（dex 041）。
# Android 16 (API 36) dex 格式与 15 相同（DEX 041），降级用 35 即可。
SMALI_API=$API_LEVEL
if [ "$SMALI_API" -ge 36 ]; then
    info "API $SMALI_API >= 36，smali 2.5.2 不支持，降级用 API 35（dex 041，兼容 Android 15/16）"
    SMALI_API=35
fi
for d in $DEX_TO_PATCH; do
    out_dir="$WORK/smali_${d%.dex}"
    out_dex="$PATCHED_OUT/$d"
    info "smali a $out_dir -> $out_dex  (API $SMALI_API)"
    java -jar "$SMALI_JAR" a -a "$SMALI_API" "$out_dir" -o "$out_dex" 2>"$WORK/smali_${d%.dex}.err" \
        || die "smali 重新打包 $d 失败: $(head -5 "$WORK/smali_${d%.dex}.err")"
    # 校验 dex magic
    magic=$(head -c 8 "$out_dex" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        6465780a3033*) ok "$d 重新打包成功 (magic=$magic, $(du -h "$out_dex" | cut -f1))";;
        *) die "$d 重新打包后 magic 异常: $magic";;
    esac
done

# ============================================================================
step "6. 从 FrameworkPatch APK 取出 classes.dex（作为 framework 的 classesN.dex）"
# ============================================================================
[ -f "$FP_APK" ] || die "FrameworkPatch APK 不存在: $FP_APK"
info "从 $FP_APK 取出 FrameworkPatch dex..."
FP_DEX="$PATCHED_OUT/frameworkpatch.dex"
unzip -o -j -q "$FP_APK" 'classes.dex' -d "$WORK/fp_extract" || die "解压 APK 失败"
cp -f "$WORK/fp_extract/classes.dex" "$FP_DEX"
ok "FrameworkPatch dex: $FP_DEX ($(du -h "$FP_DEX" | cut -f1))"

# ============================================================================
step "7. 组装新 framework.jar"
# ============================================================================
info "组装 framework.jar..."

# 确定最大 dex 编号（classes6.dex → 6），FrameworkPatch dex 用 7
max_num=0
for f in "$FW_DIR"/classes*.dex; do
    [ -f "$f" ] || continue
    n=$(basename "$f" | sed 's/classes\([0-9]*\)\.dex/\1/')
    # classes.dex → 1
    [ "$n" = "" ] && n=1
    [ "$n" -gt "$max_num" ] && max_num=$n
done
fp_num=$((max_num + 1))
info "原始 dex 最大编号: $max_num, FrameworkPatch dex 编号: $fp_num"

# 用 python 组装 zip（保证 dex STORED 不压缩 + 顺序正确）
python3 - "$FW_DIR" "$PATCHED_OUT" "$PATCHED_OUT/framework.jar" "$fp_num" <<'PYEOF'
import os, sys, zipfile

src_dir, patched_dir, out_jar, fp_num = sys.argv[1:5]
fp_num = int(fp_num)

# 收集所有 dex：patched 的覆盖原始，其余原样
dex_files = {}  # name -> path

# 原始 dex
for f in sorted(os.listdir(src_dir)):
    if f.startswith('classes') and f.endswith('.dex'):
        dex_files[f] = os.path.join(src_dir, f)

# 用 patched 版覆盖 classes.dex 和 classes3.dex
for f in sorted(os.listdir(patched_dir)):
    if f in ('classes.dex', 'classes3.dex'):
        dex_files[f] = os.path.join(patched_dir, f)

# FrameworkPatch dex 作为 classesN.dex
fp_name = 'classes{}.dex'.format(fp_num)
dex_files[fp_name] = os.path.join(patched_dir, 'frameworkpatch.dex')

# 按编号排序：classes.dex(1), classes2.dex(2), ...
def sort_key(name):
    n = name[len('classes'):-len('.dex')]
    return int(n) if n else 1

ordered = sorted(dex_files.items(), key=lambda x: sort_key(x[0]))

with zipfile.ZipFile(out_jar, 'w') as zf:
    for name, path in ordered:
        # dex 用 STORED（不压缩），ART 直接 mmap；其余也 STORED 保证兼容
        zf.write(path, name, compress_type=zipfile.ZIP_STORED)
        print('  + {} ({})'.format(name, os.path.getsize(path)))

print('framework.jar: {} ({} dex)'.format(out_jar, len(ordered)))
PYEOF

ok "framework.jar 组装完成: $PATCHED_OUT/framework.jar ($(du -h "$PATCHED_OUT/framework.jar" | cut -f1))"

# ============================================================================
step "8. zipalign"
# ============================================================================
# 优先用 SDK 的 zipalign，回退到 build-tools
ZIPALIGN=$(command -v zipalign 2>/dev/null || true)
if [ -z "$ZIPALIGN" ]; then
    SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/android-sdk}}"
    for bt in "$SDK_ROOT"/build-tools/*/zipalign; do
        [ -x "$bt" ] && ZIPALIGN="$bt" && break
    done
fi
if [ -n "$ZIPALIGN" ]; then
    info "zipalign: $ZIPALIGN"
    "$ZIPALIGN" -f -p 4 "$PATCHED_OUT/framework.jar" "$PATCHED_OUT/framework.aligned.jar"
    mv -f "$PATCHED_OUT/framework.aligned.jar" "$PATCHED_OUT/framework.jar"
    ok "zipalign 完成"
else
    warn "未找到 zipalign，跳过（STORED 模式下不影响功能，但建议 align）"
fi

# ============================================================================
step "9. 打包 Magisk 模块 zip（手机直接刷入）"
# ============================================================================
info "打包 Magisk 模块..."
mkdir -p "$MAGISK_OUT/META-INF/com/google/android"
mkdir -p "$MAGISK_OUT/system/framework"

# module.prop
cat > "$MAGISK_OUT/module.prop" <<'EOF'
id=frameworkpatch
name=FrameworkPatch (OnePlus PLC110)
version=2.0
versionCode=2
author=FrameworkPatch CI
description=Patch framework.jar to spoof BL lock / Verified Boot / Key Attestation. Hooks: AndroidKeyStoreSpi + Instrumentation + SystemProperties.
EOF

# 把 patched framework.jar 放进模块（Magisk 会覆盖 /system/framework/framework.jar）
cp -f "$PATCHED_OUT/framework.jar" "$MAGISK_OUT/system/framework/framework.jar"

# post-fs-data.sh：打印提示（实际替换由 Magisk 的 system/ 覆盖机制完成）
cat > "$MAGISK_OUT/post-fs-data.sh" <<'EOF'
#!/system/bin/sh
# FrameworkPatch: framework.jar 已由 Magisk 模块 system/ 覆盖机制替换。
# 此处无需额外操作。如开机 bootloop，在 recovery 删除本模块即可恢复。
echo "[FrameworkPatch] system/framework/framework.jar replaced."
EOF
chmod +x "$MAGISK_OUT/post-fs-data.sh"

# Magisk 模块需要 update-binary 和 updater-script
cat > "$MAGISK_OUT/META-INF/com/google/android/update-binary" <<'EOF'
#!/sbin/sh
#################
# Initialization
#################
umask 022

# echo before loading util_functions
ui_print() { echo "$1"; }

require_new_magisk() {
  ui_print "*******************************"
  ui_print " Please install Magisk v20.4+! "
  ui_print "*******************************"
  exit 1
}

#########################
# Load util_functions.sh
#########################
OUTFD=$2
ZIPFILE=$3

mount /data 2>/dev/null

[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
. /data/adb/magisk/util_functions.sh
[ $MAGISK_VER_CODE -lt 20400 ] && require_new_magisk

install_module
exit 0
EOF
chmod +x "$MAGISK_OUT/META-INF/com/google/android/update-binary"

echo '#MAGISK' > "$MAGISK_OUT/META-INF/com/google/android/updater-script"

# 打包 Magisk 模块 zip
MAGISK_ZIP="$ROOT/release/FrameworkPatch-PLC110-Magisk.zip"
mkdir -p "$(dirname "$MAGISK_ZIP")"
( cd "$MAGISK_OUT" && zip -r -q "$MAGISK_ZIP" . )
ok "Magisk 模块: $MAGISK_ZIP ($(du -h "$MAGISK_ZIP" | cut -f1))"

# 同时把 patched dex 单独拷出（便于手动替换）
cp -f "$PATCHED_OUT/classes.dex"   "$ROOT/release/classes.dex.patched"
cp -f "$PATCHED_OUT/classes3.dex"  "$ROOT/release/classes3.dex.patched"
cp -f "$FP_DEX"                    "$ROOT/release/frameworkpatch.dex"
cp -f "$PATCHED_OUT/framework.jar" "$ROOT/release/framework.jar"
ok "独立 dex 已拷到 release/"

# ============================================================================
step "10. 完成"
# ============================================================================
echo ""
echo "=== 产出文件 (release/) ==="
ls -la "$ROOT/release/"
echo ""
echo "=== 刷入方式 ==="
echo "方式1（推荐）: 下载 FrameworkPatch-PLC110-Magisk.zip，在 Magisk 里刷入，重启"
echo "方式2（手动）: 用 release/framework.jar 替换 /system/framework/framework.jar"
echo "方式3（仅替换 dex）: 把 classes.dex.patched / classes3.dex.patched / frameworkpatch.dex"
echo "           注入到现有 framework.jar（编号递增），zipalign 后替换"

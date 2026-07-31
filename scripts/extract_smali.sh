#!/bin/bash
# ============================================================================
#  FrameworkPatch smali 适配信息提取脚本
#  从 framework.jar 反编译，定位三个 hook 点，输出适配报告。
#  CI（GitHub Actions）和本地均可运行。
#
#  依赖：java、unzip、strings、baksmali.jar
#
#  用法（环境变量）：
#     FW_JAR=device_input/framework.jar \
#     BAKSMALI_JAR=baksmali.jar \
#     DEVICE_INFO=device_input/device_info.txt \
#     OUT_DIR=report \
#     bash scripts/extract_smali.sh
# ============================================================================
set -euo pipefail

FW_JAR="${FW_JAR:-device_input/framework.jar}"
BAKSMALI_JAR="${BAKSMALI_JAR:-baksmali.jar}"
DEVICE_INFO="${DEVICE_INFO:-device_input/device_info.txt}"
OUT_DIR="${OUT_DIR:-report}"
WORK="${WORK:-fw_work}"

# ---------- 颜色 ----------
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
fi
ok()   { printf "${G}[OK]${N} %s\n" "$1"; }
err()  { printf "${R}[ERR]${N} %s\n" "$1"; }
warn() { printf "${Y}[WARN]${N} %s\n" "$1"; }
info() { printf "${C}[INFO]${N} %s\n" "$1"; }
step() { printf "${BOLD}${B}>>> %s${N}\n" "$1"; }
die()  { err "$1"; exit 1; }

# ============================================================================
step "0. 环境检查"
# ============================================================================
command -v java  >/dev/null 2>&1 || die "未找到 java"
[ -f "$BAKSMALI_JAR" ]  || die "未找到 baksmali.jar: $BAKSMALI_JAR"
ok "java:   $(java -version 2>&1 | head -1)"
ok "baksmali: $BAKSMALI_JAR"

# 输入源：优先 framework.jar（完整），否则用 device_input/*.dex（分片，绕开 GitHub 25MB 限制）
DEX_INPUT_DIR="${DEX_INPUT_DIR:-device_input}"
INPUT_MODE="none"
if [ -f "$FW_JAR" ]; then
    INPUT_MODE="jar"
    command -v unzip >/dev/null 2>&1 || die "输入是 jar 但未找到 unzip"
    ok "输入模式: framework.jar ($FW_JAR, $(wc -c < "$FW_JAR") 字节)"
elif [ -d "$DEX_INPUT_DIR" ]; then
    DEX_INPUTS=$(cd "$DEX_INPUT_DIR" && ls -1 classes*.dex 2>/dev/null | sort -V)
    if [ -n "$DEX_INPUTS" ]; then
        INPUT_MODE="dex"
        DEX_INPUT_COUNT=$(echo "$DEX_INPUTS" | wc -l | tr -d ' ')
        ok "输入模式: $DEX_INPUT_COUNT 个 dex 文件 ($DEX_INPUT_DIR/，绕开 GitHub 25MB 限制)"
        echo "$DEX_INPUTS" | sed 's/^/    - /'
    fi
fi
[ "$INPUT_MODE" != "none" ] || die "未找到输入：请把 framework.jar 或 classes*.dex 放到 device_input/（手机端用 scripts/extract_dex_on_device.sh 提取 dex）"

mkdir -p "$WORK" "$OUT_DIR"

# ============================================================================
step "1. 采集输入元信息"
# ============================================================================
FW_SIZE="（dex 模式，无整体大小）"
FW_MD5="（dex 模式，无整体 MD5）"
FW_SHA256="（dex 模式，无整体 SHA256）"
if [ "$INPUT_MODE" = "jar" ]; then
    FW_SIZE=$(wc -c < "$FW_JAR")
    FW_MD5=$(md5sum "$FW_JAR" | awk '{print $1}')
    FW_SHA256=$(sha256sum "$FW_JAR" | awk '{print $1}')
    ok "大小: $FW_SIZE 字节"
    ok "MD5:    $FW_MD5"
    ok "SHA256: $FW_SHA256"
else
    # dex 模式：算所有 dex 的合并 MD5 作为指纹
    ok "dex 模式：合并 MD5: $(cat "$DEX_INPUT_DIR"/classes*.dex | md5sum | awk '{print $1}')"
    echo "各 dex 大小:"
    (cd "$DEX_INPUT_DIR" && ls -la classes*.dex 2>/dev/null) | awk '{printf "    %s  %s\n", $5, $NF}'
fi

# 设备信息（可选，用户上传 device_info.txt）
DEV_MODEL="（未提供）"
DEV_DEVICE="（未提供）"
DEV_BRAND="（未提供）"
DEV_RELEASE="（未提供）"
DEV_SDK="（未提供）"
DEV_FP="（未提供）"
DEV_SEC="（未提供）"
DEV_INCREMENTAL="（未提供）"
DEV_ID="（未提供）"
if [ -f "$DEVICE_INFO" ]; then
    info "读取设备信息: $DEVICE_INFO"
    gp() { grep -m1 "^$1=" "$DEVICE_INFO" 2>/dev/null | cut -d= -f2- | tr -d '\r'; }
    DEV_MODEL=$(gp ro.product.model)
    DEV_DEVICE=$(gp ro.product.device)
    DEV_BRAND=$(gp ro.product.brand)
    DEV_RELEASE=$(gp ro.build.version.release)
    DEV_SDK=$(gp ro.build.version.sdk)
    DEV_FP=$(gp ro.build.fingerprint)
    DEV_SEC=$(gp ro.build.version.security_patch)
    DEV_INCREMENTAL=$(gp ro.build.version.incremental)
    DEV_ID=$(gp ro.build.id)
    ok "型号: $DEV_MODEL ($DEV_BRAND/$DEV_DEVICE) Android $DEV_RELEASE (SDK $DEV_SDK)"
else
    warn "未提供 device_info.txt（可选）。建议手机上执行:"
    echo "    su -c 'getprop > /sdcard/device_info.txt' 然后上传到 device_input/"
fi

# ============================================================================
step "2. 准备 dex 文件"
# ============================================================================
FW_DIR="$WORK/framework"
rm -rf "$FW_DIR"
mkdir -p "$FW_DIR"
if [ "$INPUT_MODE" = "jar" ]; then
    info "从 framework.jar 解出 dex ..."
    unzip -o -q "$FW_JAR" -d "$FW_DIR" || die "unzip 失败"
else
    info "从 $DEX_INPUT_DIR/ 拷贝 dex ..."
    cp -f "$DEX_INPUT_DIR"/classes*.dex "$FW_DIR"/
fi

DEX_LIST=$(cd "$FW_DIR" && ls -1 classes*.dex 2>/dev/null | sort -V)
[ -n "$DEX_LIST" ] || die "未找到 classes*.dex"
DEX_COUNT=$(echo "$DEX_LIST" | wc -l | tr -d ' ')
ok "共 $DEX_COUNT 个 dex:"
echo "$DEX_LIST" | sed 's/^/    - /'

# ---- 文件头校验：dex magic = "dex\n035" / "dex\n036" / "dex\n037" / "dex\n038" ----
# 防止上传的文件已损坏（如全 0 字节、被文件管理器写坏、CRLF 篡改等）
info "校验 dex 文件头 ..."
BAD=0
for d in $DEX_LIST; do
    f="$FW_DIR/$d"
    magic=$(head -c 4 "$f" 2>/dev/null)
    ver=$(head -c 8 "$f" 2>/dev/null | tail -c 4)
    size=$(wc -c < "$f")
    if [ "$magic" != "dex
" ]; then
        # magic 不是 "dex\n"，损坏
        err "$d 文件头损坏: magic=$(printf '%s' "$magic" | od -An -tx1 | tr -d ' ') 大小=$size"
        err "  期望 magic=64 65 78 0a (dex\\n)，实际不是 → 文件已被清零/篡改/解压失败"
        BAD=$((BAD+1))
    else
        ok "$d magic=dex\\n$ver 大小=$size（正常）"
    fi
done
if [ "$BAD" -gt 0 ]; then
    echo ""
    err "检测到 $BAD 个 dex 文件已损坏（文件头不是 dex magic）"
    echo ""
    echo "=== 常见原因 ==="
    echo "1. 用 MT 管理器/X-plore 等图形工具解压 framework.jar 时出错（创建了文件但没写入数据）"
    echo "2. 用 adb pull 时中断后用空文件占位"
    echo "3. 文件管理器把 .dex 当文本处理了换行符"
    echo ""
    echo "=== 解决方法 ==="
    echo "在手机上用脚本提取（不要用文件管理器）："
    echo "  1. 下载 scripts/extract_dex_on_device.sh 到手机"
    echo "  2. su -c 'sh /sdcard/extract_dex_on_device.sh'"
    echo "  3. 该脚本会用 toybox unzip 提取，并自动校验 dex magic"
    echo "  4. 校验通过后再上传 /sdcard/device_input/ 下的 dex"
    die "存在损坏的 dex 文件，请按上述方法重新提取"
fi

# ============================================================================
step "3. 定位三个目标类所在的 dex"
# ============================================================================
declare -A CLASS_PATHS=(
    ["AndroidKeyStoreSpi"]="android/security/keystore2/AndroidKeyStoreSpi.smali"
    ["Instrumentation"]="android/app/Instrumentation.smali"
    ["SystemProperties"]="android/os/SystemProperties.smali"
)

declare -A CLASS_IN_DEX
declare -A CLASS_FOUND_FILE

for cls in "${!CLASS_PATHS[@]}"; do
    path="${CLASS_PATHS[$cls]}"
    needle="L${path%.smali};"
    found_dex=""
    for dex in $DEX_LIST; do
        if strings "$FW_DIR/$dex" 2>/dev/null | grep -qF "$needle"; then
            found_dex="$dex"
            break
        fi
    done
    if [ -n "$found_dex" ]; then
        CLASS_IN_DEX[$cls]="$found_dex"
        ok "$cls 在 $found_dex"
    else
        warn "$cls 在 strings 预扫中未命中（稍后全量反编译再找）"
        CLASS_IN_DEX[$cls]=""
    fi
done

# ============================================================================
step "4. baksmali 反编译相关 dex"
# ============================================================================
# 确定要反编译的 dex：含目标类的；若都没命中则全量
DEX_TO_DECOMPILE=""
for cls in "${!CLASS_IN_DEX[@]}"; do
    d="${CLASS_IN_DEX[$cls]}"
    [ -n "$d" ] && DEX_TO_DECOMPILE="$DEX_TO_DECOMPILE $d"
done
if [ -z "$DEX_TO_DECOMPILE" ]; then
    warn "未定位到任何目标类，全量反编译所有 dex"
    DEX_TO_DECOMPILE="$DEX_LIST"
fi
DEX_TO_DECOMPILE=$(echo "$DEX_TO_DECOMPILE" | tr ' ' '\n' | sort -u | tr '\n' ' ')
info "将反编译: $DEX_TO_DECOMPILE"

# 注：不传 -a，让 baksmali 自动解析指令格式（反编译足够；重新打包时才需精确 API level）
for dex in $DEX_TO_DECOMPILE; do
    out_dir="$WORK/smali_${dex%.dex}"
    rm -rf "$out_dir"
    info "baksmali d $dex -> $out_dir"
    if ! java -jar "$BAKSMALI_JAR" d "$FW_DIR/$dex" -o "$out_dir" 2>"$WORK/baksmali_${dex%.dex}.err"; then
        warn "baksmali 反编译 $dex 失败:"
        head -5 "$WORK/baksmali_${dex%.dex}.err" 2>/dev/null | sed 's/^/    /'
        continue
    fi
    ok "反编译完成: $out_dir ($(find "$out_dir" -name '*.smali' | wc -l) 个 smali)"
done

# ============================================================================
step "5. 在反编译结果中精确定位目标类文件"
# ============================================================================
for cls in "${!CLASS_PATHS[@]}"; do
    path="${CLASS_PATHS[$cls]}"
    found_file=""
    for out_dir in "$WORK"/smali_*; do
        [ -d "$out_dir" ] || continue
        if [ -f "$out_dir/$path" ]; then
            found_file="$out_dir/$path"
            dex_name=$(basename "$out_dir" | sed 's/^smali_//')
            CLASS_IN_DEX[$cls]="$dex_name.dex"
            break
        fi
    done
    if [ -n "$found_file" ]; then
        CLASS_FOUND_FILE[$cls]="$found_file"
        ok "$cls -> ${CLASS_IN_DEX[$cls]}"
    else
        err "$cls 未找到 smali 文件"
        CLASS_FOUND_FILE[$cls]=""
    fi
done

# ============================================================================
step "6. 提取目标方法 smali 片段"
# ============================================================================
# 从 smali 文件提取 .method ... .end method 块（匹配关键词的所有重载）
extract_method() {
    local smali_file="$1" method_kw="$2"
    [ -f "$smali_file" ] || { echo "(文件不存在: $smali_file)"; return; }
    awk -v kw="$method_kw" '
        /^[[:space:]]*\.method/ { in_method=1; method_line=$0; buf=$0"\n"; next }
        in_method {
            buf=buf $0"\n"
            if ($0 ~ /^[[:space:]]*\.end method/) {
                if (method_line ~ kw) {
                    print "--- method ---"
                    print buf
                }
                in_method=0; buf=""
            }
        }
    ' "$smali_file"
}

METHODS_MD="$WORK/_methods.md"
: > "$METHODS_MD"

emit() {
    echo ""           >> "$METHODS_MD"
    echo "### $1"     >> "$METHODS_MD"
    echo "方法签名匹配: \`$2\`" >> "$METHODS_MD"
    if [ -n "$3" ]; then
        echo "文件: \`$(echo "$3" | sed "s|$WORK/||")\`" >> "$METHODS_MD"
    fi
    echo "" >> "$METHODS_MD"
    echo '```smali' >> "$METHODS_MD"
    extract_method "$3" "$2" >> "$METHODS_MD"
    echo '```' >> "$METHODS_MD"
}

# AndroidKeyStoreSpi.engineGetCertificateChain
KS_FILE="${CLASS_FOUND_FILE[AndroidKeyStoreSpi]:-}"
if [ -n "$KS_FILE" ]; then
    info "提取 AndroidKeyStoreSpi.engineGetCertificateChain"
    emit "AndroidKeyStoreSpi.engineGetCertificateChain (所有重载)" \
         "engineGetCertificateChain" "$KS_FILE"
else
    echo "" >> "$METHODS_MD"
    echo "### AndroidKeyStoreSpi.engineGetCertificateChain" >> "$METHODS_MD"
    echo "**未找到该类**（OnePlus/ColorOS 可能用不同的 KeyStore provider，见下方扫描）" >> "$METHODS_MD"
fi

# Instrumentation.newApplication
INST_FILE="${CLASS_FOUND_FILE[Instrumentation]:-}"
if [ -n "$INST_FILE" ]; then
    info "提取 Instrumentation.newApplication"
    emit "Instrumentation.newApplication (所有重载)" \
         "newApplication" "$INST_FILE"
else
    echo "" >> "$METHODS_MD"
    echo "### Instrumentation.newApplication" >> "$METHODS_MD"
    echo "**未找到该类**" >> "$METHODS_MD"
fi

# SystemProperties.get
SP_FILE="${CLASS_FOUND_FILE[SystemProperties]:-}"
if [ -n "$SP_FILE" ]; then
    info "提取 SystemProperties.get / native_get"
    emit "SystemProperties.get(String)" \
         "get(Ljava/lang/String;)Ljava/lang/String;" "$SP_FILE"
    emit "SystemProperties.get(String, String)" \
         "get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" "$SP_FILE"
    emit "SystemProperties.native_get (内部调用，确认寄存器)" \
         "native_get" "$SP_FILE"
else
    echo "" >> "$METHODS_MD"
    echo "### SystemProperties.get" >> "$METHODS_MD"
    echo "**未找到该类**" >> "$METHODS_MD"
fi

# 扫描所有 AndroidKeyStore* / KeyStoreSpi 相关类（OEM 差异排查）
{
    echo ""
    echo "### KeyStore provider 类扫描（OEM 差异排查）"
    echo ""
    echo '```'
    for out_dir in "$WORK"/smali_*; do
        [ -d "$out_dir" ] || continue
        dex_name=$(basename "$out_dir" | sed 's/^smali_//')
        found=$(find "$out_dir" \( -name 'AndroidKeyStore*.smali' -o -name 'KeyStoreSpi*.smali' -o -name 'KeyStore*.smali' \) 2>/dev/null | sed "s|$out_dir/||" | sort -u)
        if [ -n "$found" ]; then
            echo "[$dex_name]"
            echo "$found" | sed 's/^/  /'
        fi
    done
    echo '```'
} >> "$METHODS_MD"

# ============================================================================
step "7. 生成适配报告"
# ============================================================================
REPORT="$OUT_DIR/ADAPT_REPORT.md"

{
    echo "# FrameworkPatch smali 适配报告"
    echo ""
    echo "由 \`scripts/extract_smali.sh\` 自动生成于 $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    echo "## 1. 设备信息"
    echo ""
    echo "| 项 | 值 |"
    echo "|---|---|"
    echo "| 型号 | $DEV_MODEL |"
    echo "| 品牌/设备 | $DEV_BRAND / $DEV_DEVICE |"
    echo "| Android 版本 | $DEV_RELEASE (SDK $DEV_SDK) |"
    echo "| 安全补丁 | $DEV_SEC |"
    echo "| Build ID | $DEV_ID |"
    echo "| 增量 | $DEV_INCREMENTAL |"
    echo "| 指纹 | \`$DEV_FP\` |"
    echo ""
    echo "## 2. framework.jar 元信息"
    echo ""
    echo "| 项 | 值 |"
    echo "|---|---|"
    echo "| 大小 | $FW_SIZE 字节 |"
    echo "| MD5 | \`$FW_MD5\` |"
    echo "| SHA256 | \`$FW_SHA256\` |"
    echo "| dex 数量 | $DEX_COUNT |"
    echo ""
    echo "### dex 列表"
    echo ""
    echo '```'
    echo "$DEX_LIST" | sed 's/^/  /'
    echo '```'
    echo ""
    echo "## 3. hook 点定位结果"
    echo ""
    echo "| 类 | 所在 dex | 是否找到 |"
    echo "|---|---|---|"
    for cls in AndroidKeyStoreSpi Instrumentation SystemProperties; do
        dex="${CLASS_IN_DEX[$cls]:-未找到}"
        f="${CLASS_FOUND_FILE[$cls]:-}"
        if [ -n "$f" ]; then
            status="✓ 找到"
        else
            status="✗ 未找到"
        fi
        echo "| $cls | $dex | $status |"
    done
    echo ""
    echo "## 4. 目标方法 smali 片段（核心）"
    echo ""
    echo "> 下面是从你 framework.jar 反编译出的真实 smali。"
    echo "> 上游需要这些片段来确定："
    echo "> 1. \`engineGetCertificateChain\` 末尾 leaf cert / chain 数组的寄存器编号"
    echo "> 2. \`newApplication\` 各重载里 Context 参数的寄存器编号"
    echo "> 3. \`SystemProperties.get\` 两个重载里 \`native_get\` 返回值的寄存器编号"
    echo "> "
    echo "> 拿到后即可给出**精确到寄存器**的 patch 指令。"
    echo ""
    cat "$METHODS_MD"
    echo ""
    echo "## 5. 重新打包参数"
    echo ""
    echo "- 反编译命令: \`java -jar baksmali.jar d <dex> -o <out_dir>\`"
    echo "- 重新打包命令: \`java -jar smali.jar a -a <API_LEVEL> <out_dir> -o <dex>\`"
    echo "- API level 参考: Android 15 = 35, Android 16 = 36"
    if [ "$DEV_SDK" != "（未提供）" ]; then
        echo "- 你的设备 SDK: $DEV_SDK"
    fi
    echo ""
    echo "## 6. 下一步"
    echo ""
    echo "1. 把本报告 (\`report/ADAPT_REPORT.md\`) 内容发给上游"
    echo "2. 上游根据第 4 节 smali 片段，给出每个 hook 点的精确 patch 代码"
    echo "3. 按 README 流程：baksmali → 改 smali → smali a 重打包 → 注入 framework.jar"
} > "$REPORT"

ok "报告已生成: $REPORT"
echo ""
info "报告预览（前 50 行）:"
echo "------------------------------------------------------------"
head -50 "$REPORT"
echo "------------------------------------------------------------"

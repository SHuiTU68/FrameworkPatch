#!/bin/bash
# ============================================================================
#  FrameworkPatch smali 适配信息提取脚本
#  作用：从 OnePlus 设备 pull framework.jar，反编译，定位三个 hook 点，
#        输出方法片段 + 寄存器信息，方便交给上游做设备适配。
#
#  依赖：adb / java / baksmali.jar（自动检测，缺失时给出下载命令）
#  平台：Linux / WSL / macOS
#
#  用法：
#     chmod +x extract_framework.sh
#     ./extract_framework.sh
#
#  产物：
#     ./fw_work/                    工作目录
#       ├── framework.jar           从设备 pull 的原始 jar
#       ├── framework/              unzip 解出的 dex + 资源
#       ├── smali_classes/          baksmali 反编译 classes.dex
#       ├── smali_classes2/         baksmali 反编译 classes2.dex
#       ├── ...（每个 dex 一个目录）
#       └── ADAPT_REPORT.md         ★适配报告（把这个发给我）★
# ============================================================================
set -euo pipefail

# ---------- 颜色 ----------
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; B=''; C=''; BOLD=''; N=''
fi
ok()    { printf "${G}[OK]${N} %s\n" "$1"; }
err()   { printf "${R}[ERR]${N} %s\n" "$1"; }
warn()  { printf "${Y}[WARN]${N} %s\n" "$1"; }
info()  { printf "${C}[INFO]${N} %s\n" "$1"; }
step()  { printf "${BOLD}${B}>>> %s${N}\n" "$1"; }
die()   { err "$1"; exit 1; }

WORK="$PWD/fw_work"
REPORT="$WORK/ADAPT_REPORT.md"
BAKSMALI_JAR="${BAKSMALI_JAR:-$PWD/baksmali.jar}"

print_banner() {
    echo ""
    printf "${BOLD}${C}"
    echo " ╔══════════════════════════════════════════════════════════╗"
    echo " ║   FrameworkPatch smali 适配信息提取脚本 v1.0              ║"
    echo " ║   目标：定位 AndroidKeyStoreSpi / Instrumentation /        ║"
    echo " ║         SystemProperties 三个 hook 点的 smali 片段         ║"
    echo " ╚══════════════════════════════════════════════════════════╝"
    printf "${N}"
    echo ""
}

# ============================================================================
step "0. 环境检查"
# ============================================================================
command -v adb >/dev/null 2>&1 || die "未找到 adb，请先安装 platform-tools 并加入 PATH"
command -v java >/dev/null 2>&1 || die "未找到 java，请安装 JDK 17（apt install default-jdk）"
command -v unzip >/dev/null 2>&1 || die "未找到 unzip（apt install unzip）"

JAVA_MAJOR=$(java -version 2>&1 | head -1 | awk -F['".] '{print $2}')
ok "adb:   $(adb --version 2>&1 | head -1)"
ok "java:  $(java -version 2>&1 | head -1)"
ok "unzip: $(unzip -v 2>&1 | head -1)"

if [ ! -f "$BAKSMALI_JAR" ]; then
    warn "未找到 baksmali.jar ($BAKSMALI_JAR)"
    echo ""
    echo "请下载 baksmali（任选一种）："
    echo "  方式1（推荐）：从 https://github.com/google/smali/releases 下载最新 baksmali-x.x.x-fat.jar"
    echo "  方式2：git clone --depth=1 https://github.com/google/smali.git && cd smali && ./gradlew build"
    echo "         产物在 smali/baksmali/build/libs/baksmali-*-fat.jar"
    echo ""
    echo "下载后重命名为 baksmali.jar 放到当前目录，或用环境变量："
    echo "  BAKSMALI_JAR=/path/to/baksmali.jar $0"
    echo ""
    echo "或直接用环境变量指定路径后重跑："
    echo "  BAKSMALI_JAR=/your/path/baksmali-fat.jar ./extract_framework.sh"
    exit 1
fi
ok "baksmali: $BAKSMALI_JAR"

# ============================================================================
step "1. 检测 adb 设备"
# ============================================================================
# 等待设备
adb wait-for-device 2>/dev/null || die "adb 未检测到设备，请确认 USB 连接 + adb 授权"
DEVICE_SERIAL=$(adb get-serialno 2>/dev/null || echo "unknown")
DEVICE_STATE=$(adb get-state 2>/dev/null || echo "unknown")
[ "$DEVICE_STATE" = "device" ] || die "设备状态异常: $DEVICE_STATE（需正常开机，非 recovery/sideload）"
ok "设备序列号: $DEVICE_SERIAL"

# 验证 root
ROOT_CHECK=$(adb shell 'echo "root_ok=$(id -u 2>/dev/null)"' 2>/dev/null | grep -o 'root_ok=[0-9]*' | cut -d= -f2)
if [ "$ROOT_CHECK" != "0" ]; then
    # 尝试 su
    SU_CHECK=$(adb shell 'su -c "id -u"' 2>/dev/null | tr -d '\r\n ')
    [ "$SU_CHECK" = "0" ] || die "设备未 root 或未授权 adb root/su"
fi
ok "设备已 root"

# ============================================================================
step "2. 采集设备信息"
# ============================================================================
DEV_MODEL=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')
DEV_DEVICE=$(adb shell getprop ro.product.device 2>/dev/null | tr -d '\r')
DEV_BRAND=$(adb shell getprop ro.product.brand 2>/dev/null | tr -d '\r')
DEV_RELEASE=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
DEV_SDK=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
DEV_FP=$(adb shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r')
DEV_SEC=$(adb shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r')
DEV_INCREMENTAL=$(adb shell getprop ro.build.version.incremental 2>/dev/null | tr -d '\r')
DEV_ID=$(adb shell getprop ro.build.id 2>/dev/null | tr -d '\r')

ok "型号: $DEV_MODEL ($DEV_BRAND/$DEV_DEVICE)"
ok "Android: $DEV_RELEASE (SDK $DEV_SDK)"
ok "指纹: $DEV_FP"
ok "安全补丁: $DEV_SEC  增量: $DEV_INCREMENTAL  ID: $DEV_ID"

# API level 用于 baksmali -a 参数
API_LEVEL="$DEV_SDK"
[ -n "$API_LEVEL" ] || API_LEVEL=35
info "baksmali 将使用 API level = $API_LEVEL"

# ============================================================================
step "3. pull framework.jar"
# ============================================================================
mkdir -p "$WORK"
cd "$WORK"

FW_REMOTE="/system/framework/framework.jar"
FW_LOCAL="$WORK/framework.jar"

# 检查设备上文件是否存在
FW_EXISTS=$(adb shell "test -f $FW_REMOTE && echo yes || echo no" 2>/dev/null | tr -d '\r')
[ "$FW_EXISTS" = "yes" ] || die "设备上 $FW_REMOTE 不存在"

# 先查大小
FW_SIZE=$(adb shell "stat -c %s $FW_REMOTE 2>/dev/null || wc -c < $FW_REMOTE" 2>/dev/null | tr -d '\r ')
ok "设备 framework.jar 大小: ${FW_SIZE:-未知} 字节"

# Magisk/overlay 可能替换了 framework.jar，也查一下 modules
MAGISK_FW=$(adb shell 'su -c "find /data/adb/modules -name framework.jar 2>/dev/null"' 2>/dev/null | tr -d '\r')
if [ -n "$MAGISK_FW" ]; then
    warn "检测到 Magisk 模块替换 framework.jar:"
    echo "$MAGISK_FW" | sed 's/^/    /'
fi

# adb pull（root pull 系统文件可能失败，用 cat 方式兜底）
info "正在 pull framework.jar ..."
if ! adb pull "$FW_REMOTE" "$FW_LOCAL" 2>/dev/null; then
    info "adb pull 失败，改用 su + cat 方式"
    adb shell "su -c 'cat $FW_REMOTE'" > "$FW_LOCAL" 2>/dev/null || die "pull 失败"
fi
[ -s "$FW_LOCAL" ] || die "pull 的 framework.jar 为空"
ok "已 pull 到本地: $FW_LOCAL ($(wc -c < "$FW_LOCAL") 字节)"

FW_MD5=$(md5sum "$FW_LOCAL" | awk '{print $1}')
FW_SHA256=$(sha256sum "$FW_LOCAL" | awk '{print $1}')
ok "MD5:    $FW_MD5"
ok "SHA256: $FW_SHA256"

# ============================================================================
step "4. unzip 解出 dex"
# ============================================================================
FW_DIR="$WORK/framework"
rm -rf "$FW_DIR"
mkdir -p "$FW_DIR"
unzip -o -q "$FW_LOCAL" -d "$FW_DIR" || die "unzip 失败"

# 列出所有 dex
DEX_LIST=$(cd "$FW_DIR" && ls -1 classes*.dex 2>/dev/null | sort -V)
[ -n "$DEX_LIST" ] || die "framework.jar 未含 classes*.dex"

DEX_COUNT=$(echo "$DEX_LIST" | wc -l | tr -d ' ')
ok "framework.jar 含 $DEX_COUNT 个 dex 文件:"
echo "$DEX_LIST" | sed 's/^/    - /'

# ============================================================================
step "5. baksmali 反编译每个 dex"
# ============================================================================
# 用 strings 粗定位每个目标类在哪个 dex（避免全部反编译浪费时间）
declare -A CLASS_PATHS=(
    ["AndroidKeyStoreSpi"]="android/security/keystore2/AndroidKeyStoreSpi.smali"
    ["Instrumentation"]="android/app/Instrumentation.smali"
    ["SystemProperties"]="android/os/SystemProperties.smali"
)

# 找到每个类在哪个 dex
declare -A CLASS_IN_DEX
for cls in "${!CLASS_PATHS[@]}"; do
    path="${CLASS_PATHS[$cls]}"
    # smali 里类名以 L...; 形式出现，strings 能搜到
    found_dex=""
    for dex in $DEX_LIST; do
        # strings 找 Landroid/security/keystore2/AndroidKeyStoreSpi;
        needle="L${path%.smali};"
        if strings "$FW_DIR/$dex" 2>/dev/null | grep -qF "$needle"; then
            found_dex="$dex"
            break
        fi
    done
    if [ -n "$found_dex" ]; then
        CLASS_IN_DEX[$cls]="$found_dex"
        ok "$cls 在 $found_dex"
    else
        warn "$cls 未在任何 dex 中找到（类名可能不同，稍后全量反编译再搜）"
        CLASS_IN_DEX[$cls]=""
    fi
done

# 只反编译需要的 dex（含目标类的）；若都没找到，全量反编译
DEX_TO_DECOMPILE=""
for cls in "${!CLASS_IN_DEX[@]}"; do
    d="${CLASS_IN_DEX[$cls]}"
    [ -n "$d" ] && DEX_TO_DECOMPILE="$DEX_TO_DECOMPILE $d"
done
if [ -z "$DEX_TO_DECOMPILE" ]; then
    warn "未定位到任何目标类，全量反编译所有 dex"
    DEX_TO_DECOMPILE="$DEX_LIST"
fi
# 去重
DEX_TO_DECOMPILE=$(echo "$DEX_TO_DECOMPILE" | tr ' ' '\n' | sort -u | tr '\n' ' ')

info "将反编译: $DEX_TO_DECOMPILE"

for dex in $DEX_TO_DECOMPILE; do
    out_dir="$WORK/smali_${dex%.dex}"
    rm -rf "$out_dir"
    info "baksmali d $dex -> $out_dir"
    if ! java -jar "$BAKSMALI_JAR" d "$FW_DIR/$dex" -a "$API_LEVEL" -o "$out_dir" 2>"$WORK/baksmali_${dex%.dex}.err"; then
        warn "baksmali 反编译 $dex 失败（见 $WORK/baksmali_${dex%.dex}.err）"
        cat "$WORK/baksmali_${dex%.dex}.err" 2>/dev/null | head -5 | sed 's/^/    /'
        # 可能是 API level 不对，尝试不带 -a
        info "尝试不带 -a 参数重试 ..."
        if ! java -jar "$BAKSMALI_JAR" d "$FW_DIR/$dex" -o "$out_dir" 2>"$WORK/baksmali_${dex%.dex}.err"; then
            err "baksmali 反编译 $dex 彻底失败"
            continue
        fi
    fi
    ok "反编译完成: $out_dir ($(find "$out_dir" -name '*.smali' | wc -l) 个 smali 文件)"
done

# ============================================================================
step "6. 全量搜索三个目标类（确认位置）"
# ============================================================================
# 重新在反编译结果里找，更准确
declare -A CLASS_FOUND_FILE
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
        ok "$cls -> ${CLASS_IN_DEX[$cls]} : $found_file"
    else
        err "$cls 未找到 smali 文件（类路径可能不同）"
        CLASS_FOUND_FILE[$cls]=""
    fi
done

# ============================================================================
step "7. 提取目标方法 smali 片段"
# ============================================================================
# 工具：从 smali 文件中提取指定方法的完整代码块
# 用法: extract_method <smali_file> <method_signature_keyword>
extract_method() {
    local smali_file="$1" method_kw="$2"
    [ -f "$smali_file" ] || { echo "(文件不存在: $smali_file)"; return; }
    # 找 .method 行，输出到对应 .end method
    awk -v kw="$method_kw" '
        /^[[:space:]]*\.method/ {
            in_method=1; method_line=$0; buf=$0"\n"; start=NR; next
        }
        in_method {
            buf=buf $0"\n"
            if ($0 ~ /^[[:space:]]*\.end method/) {
                if (method_line ~ kw) {
                    print "--- method (line " start ") ---"
                    print buf
                    return
                }
                in_method=0; buf=""
            }
        }
    ' "$smali_file"
}

# 提取并标注寄存器
extract_with_reg_hints() {
    local smali_file="$1" method_kw="$2" label="$3"
    echo ""
    echo "### $label"
    echo "方法关键词: \`$method_kw\`"
    echo "文件: \`$(echo "$smali_file" | sed "s|$WORK/||")\`"
    echo ""
    echo '```smali'
    extract_method "$smali_file" "$method_kw"
    echo '```'
}

# ---- AndroidKeyStoreSpi: engineGetCertificateChain ----
KS_FILE="${CLASS_FOUND_FILE[AndroidKeyStoreSpi]:-}"
if [ -n "$KS_FILE" ]; then
    info "提取 AndroidKeyStoreSpi.engineGetCertificateChain ..."
    # 该方法可能有多个重载，全提取
    extract_with_reg_hints "$KS_FILE" "engineGetCertificateChain" "AndroidKeyStoreSpi.engineGetCertificateChain" >> "$WORK/_methods.md"
fi

# ---- Instrumentation: newApplication ----
INST_FILE="${CLASS_FOUND_FILE[Instrumentation]:-}"
if [ -n "$INST_FILE" ]; then
    info "提取 Instrumentation.newApplication ..."
    extract_with_reg_hints "$INST_FILE" "newApplication" "Instrumentation.newApplication (所有重载)" >> "$WORK/_methods.md"
fi

# ---- SystemProperties: get ----
SP_FILE="${CLASS_FOUND_FILE[SystemProperties]:-}"
if [ -n "$SP_FILE" ]; then
    info "提取 SystemProperties.get ..."
    # 两个关键重载
    extract_with_reg_hints "$SP_FILE" "get(Ljava/lang/String;)Ljava/lang/String;" "SystemProperties.get(String)" >> "$WORK/_methods.md"
    extract_with_reg_hints "$SP_FILE" "get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" "SystemProperties.get(String, String)" >> "$WORK/_methods.md"
    # 顺便提取 native_get 声明，确认寄存器
    extract_with_reg_hints "$SP_FILE" "native_get" "SystemProperties.native_get (内部调用)" >> "$WORK/_methods.md"
fi

# 如果都没找到，写个占位
if [ ! -s "$WORK/_methods.md" ]; then
    echo "（未找到任何目标方法，可能类路径在 该 OEM 上不同）" > "$WORK/_methods.md"
fi

# ============================================================================
step "8. 检查类是否有 OEM 差异（类名/包名）"
# ============================================================================
# OnePlus/ColorOS 可能用 android.security.keystore2.AndroidKeyStoreSpi
# 也可能旧版用 android.security.KeyStore (Android < 12)
info "扫描可能的 KeyStore provider 类 ..."
{
    echo ""
    echo "### KeyStore provider 类扫描"
    echo ""
    echo '```'
    for out_dir in "$WORK"/smali_*; do
        [ -d "$out_dir" ] || continue
        dex_name=$(basename "$out_dir" | sed 's/^smali_//')
        # 找所有 AndroidKeyStore* / KeyStoreSpi 相关
        found=$(find "$out_dir" -name 'AndroidKeyStore*.smali' -o -name 'KeyStoreSpi*.smali' 2>/dev/null | sed "s|$out_dir/||" | sort -u)
        if [ -n "$found" ]; then
            echo "[$dex_name]"
            echo "$found" | sed 's/^/  /'
        fi
    done
    echo '```'
} >> "$WORK/_methods.md"

# ============================================================================
step "9. 生成适配报告"
# ============================================================================
{
    echo "# FrameworkPatch smali 适配报告"
    echo ""
    echo "由 \`extract_framework.sh\` 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')"
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
    echo "| 序列号 | $DEVICE_SERIAL |"
    echo ""
    echo "## 2. framework.jar 信息"
    echo ""
    echo "| 项 | 值 |"
    echo "|---|---|"
    echo "| 路径(设备) | $FW_REMOTE |"
    echo "| 大小 | $(wc -c < "$FW_LOCAL") 字节 |"
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
    if [ -n "$MAGISK_FW" ]; then
        echo "### Magisk 模块替换"
        echo ""
        echo '```'
        echo "$MAGISK_FW" | sed 's/^/  /'
        echo '```'
        echo ""
    fi
    echo "## 3. hook 点定位结果"
    echo ""
    echo "| 类 | 所在 dex | smali 文件路径 |"
    echo "|---|---|---|"
    for cls in AndroidKeyStoreSpi Instrumentation SystemProperties; do
        dex="${CLASS_IN_DEX[$cls]:-未找到}"
        f="${CLASS_FOUND_FILE[$cls]:-}"
        rel=$(echo "$f" | sed "s|$WORK/||" 2>/dev/null)
        echo "| $cls | $dex | \`$rel\` |"
    done
    echo ""
    echo "## 4. baksmali 反编译参数"
    echo ""
    echo '- 反编译命令: `java -jar baksmali.jar d <dex> -a '"$API_LEVEL"' -o <out_dir>`'
    echo "- API level: $API_LEVEL (重新打包时 \`smali.jar a -a $API_LEVEL\` 用同一值)"
    echo ""
    echo "## 5. 目标方法 smali 片段（核心，请重点看这部分）"
    echo ""
    echo "> 下面是从你设备 framework.jar 反编译出的真实 smali。"
    echo "> 我需要这些片段来告诉你："
    echo "> 1. \`engineGetCertificateChain\` 末尾的 leaf cert 寄存器是哪个（v2/v3/...）"
    echo "> 2. \`newApplication\` 各重载的 Context 寄存器是哪个"
    echo "> 3. \`SystemProperties.get\` 两个重载里 native_get 返回值寄存器是哪个"
    echo "> "
    echo "> 拿到后我就能写出**精确到寄存器**的 patch 指令。"
    echo ""
    cat "$WORK/_methods.md"
    echo ""
    echo "## 6. 下一步"
    echo ""
    echo "1. 把本文件 (\`ADAPT_REPORT.md\`) 内容发给我"
    echo "2. 我会根据第 5 节的 smali 片段，给出每个 hook 点的精确 patch 代码"
    echo "3. 你按 README 流程：baksmali → 改 smali → smali a 重打包 → 注入 framework.jar"
    echo ""
    echo "## 7. 文件清单（工作目录）"
    echo ""
    echo '```'
    echo "工作目录: $WORK"
    echo "  framework.jar              原始 jar"
    echo "  framework/                 unzip 产物"
    for d in "$WORK"/smali_*; do
        [ -d "$d" ] && echo "  $(basename "$d")/                baksmali 反编译结果"
    done
    echo "  ADAPT_REPORT.md           本报告"
    echo '```'
} > "$REPORT"

# ============================================================================
step "10. 完成"
# ============================================================================
echo ""
ok "完成！适配报告已生成: $REPORT"
echo ""
printf "${BOLD}${G}  请把 ADAPT_REPORT.md 的内容发给我${N}\n"
echo "  我会根据第 5 节的 smali 片段，给出每个 hook 点精确到寄存器的 patch 代码"
echo ""
info "报告预览（前 60 行）:"
echo "------------------------------------------------------------"
head -60 "$REPORT"
echo "------------------------------------------------------------"
echo ""
info "完整报告路径: $REPORT"
info "工作目录: $WORK（含 framework.jar、反编译结果，可备查）"
echo ""

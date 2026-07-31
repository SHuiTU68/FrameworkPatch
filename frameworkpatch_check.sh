#!/system/bin/sh
# ============================================================================
#  FrameworkPatch 综合检测脚本
#  适用：已 root 的 OnePlus 设备（OnePlus Ace 5 至尊版 / PLC110）
#  用法：
#     su -c "sh /sdcard/frameworkpatch_check.sh"
#     或: adb shell su -c "sh /sdcard/frameworkpatch_check.sh"
#  说明：
#     - 本脚本通过 getprop / resetprop -p 读取「真实」prop 值（不经 Framework hook）
#     - FrameworkPatch 的 SystemProperties.get hook 仅在 GMS unstable 进程内生效，
#       所以这里看到的是设备底层真实状态；若你想验证 hook 是否生效，
#       请用「应用层 SystemProperties.get 读取」对比（脚本末尾给出方法）
# ============================================================================

# ---------- 颜色 ----------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

PASS=0; FAIL=0; WARN=0; INFO=0

# ---------- 工具函数 ----------
log_pass() { printf "${GREEN}[PASS]${NC} %s${NC}\n" "$1"; PASS=$((PASS+1)); }
log_fail() { printf "${RED}[FAIL]${NC} %s${NC}\n" "$1"; FAIL=$((FAIL+1)); }
log_warn() { printf "${YELLOW}[WARN]${NC} %s${NC}\n" "$1"; WARN=$((WARN+1)); }
log_info() { printf "${CYAN}[INFO]${NC} %s${NC}\n" "$1"; INFO=$((INFO+1)); }
log_line() { printf "${BLUE}%s${NC}\n" "$1"; }

print_header() {
    echo ""
    log_line "============================================================"
    printf "${BOLD}${BLUE}  %s${NC}\n" "$1"
    log_line "============================================================"
}

# 读取真实 prop（优先 resetprop -p，回退 getprop）
# resetprop -p 直接读 /dev/__properties__，绕过 magiskhide/zygisk 属性伪装
get_real_prop() {
    if command -v resetprop >/dev/null 2>&1; then
        resetprop -p "$1" 2>/dev/null
    else
        getprop "$1" 2>/dev/null
    fi
}

# 比对 prop 值
# $1 = key, $2 = expected, $3 = 是否强校验(1=必须等于, 0=仅展示)
check_prop_eq() {
    local key="$1" expected="$2" strict="$3"
    local actual
    actual=$(get_real_prop "$key")
    if [ -z "$actual" ]; then
        if [ "$strict" = "1" ]; then
            log_fail "$key = (空)  期望: $expected"
        else
            log_warn "$key 不存在（空）"
        fi
        return
    fi
    if [ "$actual" = "$expected" ]; then
        log_pass "$key = $actual"
    else
        if [ "$strict" = "1" ]; then
            log_fail "$key = $actual  期望: $expected"
        else
            log_warn "$key = $actual  期望: $expected（非关键）"
        fi
    fi
}

# 检查 prop 不包含某子串（contains 反向校验）
# $1 = key, $2 = 不应包含的子串
check_prop_not_contains() {
    local key="$1" bad="$2"
    local actual
    actual=$(get_real_prop "$key")
    if [ -z "$actual" ]; then
        log_warn "$key 不存在"
        return
    fi
    case "$actual" in
        *"$bad"*) log_fail "$key = $actual  （包含禁用子串: $bad）";;
        *) log_pass "$key = $actual  （不含 $bad）";;
    esac
}

# 检查 prop 存在且非空（设备相关）
check_prop_exists() {
    local key="$1" label="$2"
    local actual
    actual=$(get_real_prop "$key")
    if [ -n "$actual" ]; then
        log_pass "$label: $key = $actual"
    else
        log_warn "$label: $key 为空"
    fi
}

# ============================================================================
echo ""
printf "${BOLD}${CYAN}"
echo " ╔══════════════════════════════════════════════════════════╗"
echo " ║          FrameworkPatch 综合检测脚本 v1.0                 ║"
echo " ║          目标: OnePlus Ace 5 至尊版 (PLC110)              ║"
echo " ╚══════════════════════════════════════════════════════════╝"
printf "${NC}"
echo " 执行时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo " 执行者: $(id -un 2>/dev/null)  UID=$(id -u 2>/dev/null)"

# ============================================================================
print_header "1. Root 与 Magisk 状态"
# ============================================================================
if [ "$(id -u)" != "0" ]; then
    log_fail "未以 root 运行（uid=$(id -u)）。请用 su -c 执行"
    echo ""
    echo "正确用法: su -c \"sh $0\""
    exit 1
fi
log_pass "已获得 root 权限"

# Magisk
MAGISK_VER=""
if command -v magisk >/dev/null 2>&1; then
    MAGISK_VER=$(magisk -v 2>/dev/null)
    log_pass "Magisk 已安装: $MAGISK_VER"
else
    log_warn "未在 PATH 找到 magisk 二进制（可能用 KernelSU/APatch）"
fi

# Magisk/zygisk 数据目录
for d in /data/adb/magisk /data/adb/ksu /data/adb/ap; do
    if [ -d "$d" ]; then
        log_info "root 框架目录存在: $d"
    fi
done

# MagiskHide / DenyList
if command -v magisk >/dev/null 2>&1; then
    if magisk --denylist status >/dev/null 2>&1; then
        log_pass "DenyList 已启用"
    else
        log_warn "DenyList 未启用（建议为 GMS 进程开启）"
    fi
    if magisk --denylist ls 2>/dev/null | grep -q "com.google.android.gms"; then
        log_pass "GMS 已加入 DenyList"
    else
        log_warn "GMS 未加入 DenyList"
    fi
fi

# zygisk
if [ -f /data/adb/magisk.db ]; then
    ZYGISK=$(magisk --sqlite "SELECT value FROM settings WHERE key='zygisk';" 2>/dev/null | grep -o 'value=[0-9]' | cut -d= -f2)
    if [ "$ZYGISK" = "1" ]; then
        log_pass "Zygisk 已启用"
    else
        log_warn "Zygisk 未启用（zygisk=$ZYGISK）"
    fi
fi

# ============================================================================
print_header "2. SELinux 状态"
# ============================================================================
SELINUX_MODE=$(getenforce 2>/dev/null)
if [ "$SELINUX_MODE" = "Enforcing" ]; then
    log_pass "SELinux: Enforcing"
else
    log_fail "SELinux: $SELINUX_MODE  期望: Enforcing（解锁/改系统常被检测）"
fi
# 检查是否被 setenforce 0 临时关闭
if [ -f /sys/fs/selinux/enforce ]; then
    ENF=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    if [ "$ENF" = "1" ]; then
        log_pass "/sys/fs/selinux/enforce = 1"
    else
        log_fail "/sys/fs/selinux/enforce = 0（被关闭）"
    fi
fi

# ============================================================================
print_header "3. 设备指纹（OnePlus Ace 5 至尊版 PLC110 期望值）"
# ============================================================================
# 期望（与 Android.java Profile 0 一致）：
#   brand=OnePlus, device=PLC110, product=OP60EDL1, model=PLC110
#   fingerprint=OnePlus/PLC110/OP60EDL1:16/BP2A.250605.015/V.1be4275_8cb9c6_8ac72d:user/release-keys
check_prop_eq "ro.product.brand"        "OnePlus" 1
check_prop_eq "ro.product.manufacturer" "OnePlus" 1
check_prop_eq "ro.product.device"       "PLC110"  1
check_prop_eq "ro.product.name"         "OP60EDL1" 1
check_prop_eq "ro.product.model"        "PLC110"  1
check_prop_eq "ro.build.fingerprint"    "OnePlus/PLC110/OP60EDL1:16/BP2A.250605.015/V.1be4275_8cb9c6_8ac72d:user/release-keys" 1
check_prop_eq "ro.build.version.release" "16" 1
check_prop_eq "ro.build.id"             "BP2A.250605.015" 1
check_prop_eq "ro.build.version.incremental" "V.1be4275_8cb9c6_8ac72d" 1
check_prop_eq "ro.build.version.security_patch" "2025-06-05" 1
check_prop_eq "ro.build.type"           "user" 1
check_prop_eq "ro.build.tags"           "release-keys" 1

# ============================================================================
print_header "4. BL 锁 / Verified Boot 状态（核心）"
# ============================================================================
# 这些 prop 决定 DroidGuard/Play Integrity 的 BASIC_INTEGRITY 判定
check_prop_eq "ro.boot.verifiedbootstate"       "green"   1
check_prop_eq "ro.boot.flash.locked"            "1"       1
check_prop_eq "ro.boot.vbmeta.device_state"     "locked"  1
check_prop_eq "vendor.boot.vbmeta.device_state" "locked"  1
check_prop_eq "vendor.boot.verifiedbootstate"   "green"   1
check_prop_eq "ro.boot.veritymode"              "enforcing" 1
check_prop_eq "ro.boot.space.veritymode"        "enforcing" 1

# ============================================================================
print_header "5. Warranty / OEM Unlock 痕迹"
# ============================================================================
check_prop_eq "ro.boot.warranty_bit"        "0" 1
check_prop_eq "ro.warranty_bit"             "0" 1
check_prop_eq "ro.vendor.boot.warranty_bit" "0" 1
check_prop_eq "ro.vendor.warranty_bit"      "0" 1
check_prop_eq "sys.oem_unlock_allowed"      "0" 1

# bootloader unlock 实际状态（fastboot 模式可见，正常开机为空或 0）
BL_UNLOCKED=$(get_real_prop "ro.boot.flash.locked")
if [ "$BL_UNLOCKED" = "1" ]; then
    log_pass "ro.boot.flash.locked=1（已伪装为已锁）"
else
    log_fail "ro.boot.flash.locked=$BL_UNLOCKED  真实状态可能为解锁"
fi

# ============================================================================
print_header "6. Debuggable / Secure / ADB"
# ============================================================================
check_prop_eq "ro.debuggable"        "0" 1
check_prop_eq "ro.force.debuggable"  "0" 1
check_prop_eq "ro.secure"            "1" 1
check_prop_eq "ro.adb.secure"        "1" 1
check_prop_eq "ro.boot.secure"       "1" 1
check_prop_eq "ro.boot.cpuraw"       "0" 1
check_prop_eq "ro.boot.cab_mask"     "0" 1

# ro.debuggable 是 root 检测最强信号之一
if [ "$(get_real_prop ro.debuggable)" = "1" ]; then
    log_fail "ro.debuggable=1 → 这是 userdebug/eng 构建，几乎必被检测"
fi

# ============================================================================
print_header "7. Build Type / Tags / SELinux build flag"
# ============================================================================
check_prop_eq "ro.build.type"     "user"        1
check_prop_eq "ro.build.tags"     "release-keys" 1
check_prop_eq "ro.build.selinux"  "1"           1

# ============================================================================
print_header "8. OEM 专用锁状态 prop（多品牌覆盖）"
# ============================================================================
# 即使非该品牌设备，这些 prop 也应保持「已锁」语义
check_prop_eq "ro.secureboot.lockstate"   "locked" 0   # MIUI
check_prop_eq "ro.boot.realmebootstate"   "green"  0   # Realme
check_prop_eq "ro.boot.realme.lockstate"  "1"      0   # Realme
check_prop_eq "ro.boot.ftm_mode"          "unknown" 0

# ============================================================================
print_header "9. 启动模式 / 启动原因"
# ============================================================================
check_prop_eq "ro.boot.mode"       "normal" 1
check_prop_eq "ro.boot.bootreason" ""       1

# ============================================================================
print_header "10. Contains 逻辑校验（隐藏 recovery 启动痕迹）"
# ============================================================================
# Android.java 中: 原值含 "recovery" → 替换为 "unknown"
# 这里校验底层真实值是否含 recovery（resetprop 改过应不含）
check_prop_not_contains "ro.bootmode"        "recovery"
check_prop_not_contains "ro.boot.bootmode"   "recovery"
check_prop_not_contains "vendor.boot.bootmode" "recovery"

# ============================================================================
print_header "11. 设备相关 prop（OnePlus Ace 5 至尊版 Profile）"
# ============================================================================
# Profile 0 中 BOARD/BOOTLOADER/HARDWARE 留空（initDeviceProps 跳过空值）
# 这里仅展示真实值，供你判断是否需要 resetprop 强制覆盖
echo "  以下为设备真实值（FrameworkPatch Profile 0 未写入这些字段）："
RAW_BL=$(get_real_prop "ro.boot.bootloader")
RAW_HW=$(get_real_prop "ro.boot.hardware")
RAW_BOARD=$(get_real_prop "ro.product.board")
log_info "ro.boot.bootloader   = ${RAW_BL:-（空）}"
log_info "ro.boot.hardware     = ${RAW_HW:-（空）}"
log_info "ro.product.board     = ${RAW_BOARD:-（空）}"
log_info "ro.product.bootloader= $(get_real_prop ro.product.bootloader)"

# OnePlus 真实硬件 prop（ColorOS 特有）
log_info "ro.boot.hardware.sku = $(get_real_prop ro.boot.hardware.sku)"
log_info "ro.board.platform    = $(get_real_prop ro.board.platform)"
log_info "ro.soc.manufacturer  = $(get_real_prop ro.soc.manufacturer)"
log_info "ro.soc.model         = $(get_real_prop ro.soc.model)"

# ============================================================================
print_header "12. Framework.jar 注入状态（FrameworkPatch 核心）"
# ============================================================================
FW_JAR="/system/framework/framework.jar"
if [ ! -f "$FW_JAR" ]; then
    log_fail "未找到 $FW_JAR"
else
    log_pass "framework.jar 存在: $FW_JAR"
    # 检查是否含我们注入的类（com.android.internal.util.framework.Android）
    # 需要 dexdump 或 baksmali；这里用 unzip + grep dex 头做粗检
    TMPDIR=$(mktemp -d 2>/dev/null || echo /data/local/tmp/fwp_check_$$)
    mkdir -p "$TMPDIR"
    # 列出 framework.jar 内的 dex
    DEX_LIST=$(unzip -l "$FW_JAR" 2>/dev/null | grep -oE 'classes[0-9]*\.dex' | sort -u)
    if [ -z "$DEX_LIST" ]; then
        log_warn "framework.jar 未含 classes*.dex（可能是无 dex 的占位 jar）"
    else
        log_info "framework.jar 内 dex 文件:"
        echo "$DEX_LIST" | while read d; do echo "    - $d"; done
        # 解出所有 dex，用 strings 找我们的类名
        FOUND=0
        for d in $DEX_LIST; do
            unzip -p "$FW_JAR" "$d" 2>/dev/null > "$TMPDIR/$d"
            if strings "$TMPDIR/$d" 2>/dev/null | grep -q "Lcom/android/internal/util/framework/Android"; then
                log_pass "在 $d 中找到注入类 com/android/internal/util/framework/Android"
                FOUND=1
            fi
        done
        if [ "$FOUND" = "0" ]; then
            log_fail "framework.jar 未注入 FrameworkPatch 类（patch 未生效）"
        fi
    fi
    rm -rf "$TMPDIR" 2>/dev/null
fi

# 检查是否有 overlay/magisk module 替换 framework.jar
MAGISK_FW_MOD=$(find /data/adb/modules -type f -name "framework.jar" 2>/dev/null | head -1)
if [ -n "$MAGISK_FW_MOD" ]; then
    log_info "Magisk 模块替换 framework.jar: $MAGISK_FW_MOD"
fi

# ============================================================================
print_header "13. AVB / dm-verity 实际状态"
# ============================================================================
# /proc/cmdline 中的 androidboot.verifiedbootstate 是 bootloader 真实上报值
if [ -r /proc/cmdline ]; then
    CMDLINE=$(cat /proc/cmdline 2>/dev/null)
    VBSTATE=$(echo "$CMDLINE" | grep -oE 'androidboot.verifiedbootstate=[^ ]+' | cut -d= -f2)
    FLASH_LOCKED=$(echo "$CMDLINE" | grep -oE 'androidboot.flash.locked=[^ ]+' | cut -d= -f2)
    DEV_STATE=$(echo "$CMDLINE" | grep -oE 'androidboot.vbmeta.device_state=[^ ]+' | cut -d= -f2)
    VERITY=$(echo "$CMDLINE" | grep -oE 'androidboot.veritymode=[^ ]+' | cut -d= -f2)
    log_info "/proc/cmdline androidboot.verifiedbootstate = ${VBSTATE:-（无）}"
    log_info "/proc/cmdline androidboot.flash.locked       = ${FLASH_LOCKED:-（无）}"
    log_info "/proc/cmdline androidboot.vbmeta.device_state= ${DEV_STATE:-（无）}"
    log_info "/proc/cmdline androidboot.veritymode         = ${VERITY:-（无）}"
    # cmdline 是 bootloader 真实写入，resetprop 改不了！这是最强检测点
    if [ -n "$VBSTATE" ] && [ "$VBSTATE" != "green" ]; then
        log_fail "cmdline 中 verifiedbootstate=$VBSTATE（bootloader 真实状态，resetprop 无法改）"
    fi
    if [ -n "$FLASH_LOCKED" ] && [ "$FLASH_LOCKED" != "1" ]; then
        log_fail "cmdline 中 flash.locked=$FLASH_LOCKED（bootloader 真实状态，无法隐藏）"
    fi
else
    log_warn "无法读取 /proc/cmdline"
fi

# dm-verity
for dev in /sys/block/dm-0 /sys/block/dm-1; do
    if [ -d "$dev" ]; then
        NAME=$(cat "$dev/dm/name" 2>/dev/null)
        log_info "dm 设备: $(basename $dev) name=${NAME:-unknown}"
    fi
done

# verity 状态（需 veritysetup 或读 /sys）
if command -v veritysetup >/dev/null 2>&1; then
    log_info "veritysetup 可用"
fi

# ============================================================================
print_header "14. Keybox / Key Attestation 相关"
# ============================================================================
# FrameworkPatch 通过 hook AndroidKeyStoreSpi.engineGetCertificateChain 注入伪造证书链
# 这里只能检查框架层是否被 patch（已在第 12 节做过）
# 真正的 attestation 验证需在 app 内调用 Keystore（脚本无法直接测）
KA_CLASS="android.security.keystore2.AndroidKeyStoreSpi"
log_info "Key Attestation hook 点: $KA_CLASS"
log_info "若第 12 节 framework.jar 检查通过，则 attestation hook 已注入"
log_info "完整 attestation 验证需安装 Key Attestation 应用（如 GrapheneOS KeyAttestation）"

# ============================================================================
print_header "15. ColorOS / OnePlus 特有检测点"
# ============================================================================
# ColorOS / OPlus 系特有的检测 prop
OPLUS_PROPS="
ro.product.oem_model
ro.product.oem_device
ro.product.oem.name
ro.product.odm.brand
ro.product.odm.manufacturer
ro.product.odm.device
ro.product.odm.model
ro.product.system.brand
ro.product.system.manufacturer
ro.product.system_ext.device
ro.product.vendor.brand
ro.product.vendor.manufacturer
ro.product.vendor.device
ro.product.vendor.model
ro.boot.product.hardware.sku
ro.boot.product.name
ro.boot.product.device
persist.sys.oem.region
ro.build.product"
echo "$OPLUS_PROPS" | while read p; do
    [ -z "$p" ] && continue
    v=$(get_real_prop "$p")
    if [ -n "$v" ]; then
        # 期望 brand/device/model 与 PLC110 一致
        case "$p" in
            *brand*|*manufacturer*) [ "$v" = "OnePlus" ] && log_pass "$p = $v" || log_warn "$p = $v（期望 OnePlus）";;
            *device*|*model*)       [ "$v" = "PLC110" ] && log_pass "$p = $v" || log_warn "$p = $v（期望 PLC110）";;
            *) log_info "$p = $v";;
        esac
    fi
done

# ColorOS 版本
log_info "ro.build.version.ota = $(get_real_prop ro.build.version.ota)"
log_info "ro.build.version.oplus = $(get_real_prop ro.build.version.oplus)"
log_info "ro.build.version.release_type = $(get_real_prop ro.build.version.release_type)"

# ============================================================================
print_header "16. 临时文件 / Magisk 模块残留"
# ============================================================================
# 检查 /data/local/tmp 下可疑脚本（如 test.sh 等运行痕迹）
TMP_SUSPECT=$(ls /data/local/tmp/ 2>/dev/null | grep -iE 'test|fwp|framework|patch|spoof' | head -5)
if [ -n "$TMP_SUSPECT" ]; then
    log_warn "/data/local/tmp 发现可疑文件:"
    echo "$TMP_SUSPECT" | while read f; do echo "    - $f"; done
fi

# Magisk 模块列表
if [ -d /data/adb/modules ]; then
    log_info "已安装 Magisk 模块:"
    ls -1 /data/adb/modules/ 2>/dev/null | while read m; do
        DISABLED=""
        [ -f "/data/adb/modules/$m/disable" ] && DISABLED=" [DISABLED]"
        echo "    - $m$DISABLED"
    done
fi

# ============================================================================
print_header "17. resetprop 是否生效（若你额外跑了 resetprop 脚本）"
# ============================================================================
# resetprop -p 写入的值会持久化到属性区，getprop 能读到
# FrameworkPatch 的 SystemProperties.get hook 仅在 GMS 进程内生效，
# 若想让所有读取者都看到伪装值，需配合 resetprop 全局写入
if command -v resetprop >/dev/null 2>&1; then
    log_pass "resetprop 可用: $(resetprop -v 2>/dev/null | head -1)"
    # 测试一个关键 prop 是否被 resetprop 改过
    FLASH_LOCKED=$(resetprop -p ro.boot.flash.locked 2>/dev/null)
    if [ "$FLASH_LOCKED" = "1" ]; then
        log_pass "resetprop 读取 ro.boot.flash.locked = 1（已伪装）"
    else
        log_warn "resetprop 读取 ro.boot.flash.locked = ${FLASH_LOCKED:-（空）}"
        log_info "若要全局隐藏，可执行（持久化需写 init 脚本）:"
        echo "    resetprop -p ro.boot.flash.locked 1"
        echo "    resetprop -p ro.boot.verifiedbootstate green"
        echo "    resetprop -p ro.boot.vbmeta.device_state locked"
    fi
else
    log_warn "resetprop 不可用（非 Magisk root？）"
fi

# ============================================================================
print_header "18. 总结"
# ============================================================================
echo ""
log_line "------------------------------------------------------------"
printf "${BOLD}  PASS: ${GREEN}%d${NC}    ${BOLD}FAIL: ${RED}%d${NC}    ${BOLD}WARN: ${YELLOW}%d${NC}    ${BOLD}INFO: ${CYAN}%d${NC}\n" \
    "$PASS" "$FAIL" "$WARN" "$INFO"
log_line "------------------------------------------------------------"
echo ""

if [ "$FAIL" -eq 0 ]; then
    printf "${GREEN}${BOLD}  ✓ 所有关键检查通过${NC}\n"
else
    printf "${RED}${BOLD}  ✗ 有 %d 项检查未通过${NC}\n" "$FAIL"
fi

echo ""
printf "${CYAN}  --- 重要提示 ---${NC}\n"
echo "1. getprop/resetprop 读到的是底层真实值，不受 FrameworkPatch hook 影响"
echo "   （hook 仅在 com.google.android.gms unstable 进程内生效）"
echo "2. /proc/cmdline 中的 androidboot.* 由 bootloader 写入，resetprop 无法修改"
echo "   这是 Play Integrity STRONG 判定的最终依据，已解锁设备无法绕过"
echo "3. FrameworkPatch 解决的是「应用层 SystemProperties.get 调用 + Key Attestation」"
echo "   对 GMS 之外的检测（如直接读 /proc/cmdline）无能为力"
echo "4. 若需全局隐藏 prop，配合 resetprop 脚本（见第 17 节）"
echo "5. 验证 attestation 是否生效，安装 Key Attestation 应用实测"
echo ""
printf "${CYAN}  --- 验证 FrameworkPatch hook 是否生效（在 GMS 进程内）---${NC}\n"
echo "由于 hook 仅在 GMS unstable 进程生效，需在该进程内读 SystemProperties.get："
echo "  方法1: logcat -s chiteroman （看 hook 初始化日志）"
echo "  方法2: 安装 Play Integrity API 检测应用跑 BASIC/DEVICE_INTEGRITY"
echo "  方法3: adb shell dumpsys activity processes | grep gms:unstable"
echo "         确认进程存在后，hook 才会激活"
echo ""
exit 0

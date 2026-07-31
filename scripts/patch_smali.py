#!/usr/bin/env python3
"""
精确 patch framework smali，注入 FrameworkPatch 的 5 个 hook 点。

基于 ADAPT_REPORT.md 里 OnePlus PLC110 (Android 16 / SDK 36) 的真实 smali，
按「锚点连续行匹配 + 在锚点后插入」的方式 patch，幂等（已 patch 则跳过）。

所有 patch 都复用已有寄存器，不改变 .registers 声明。

用法:
    python3 patch_smali.py <smali_classes_dir> <smali_classes3_dir>

退出码:
    0 = 全部成功（或已 patch 跳过）
    1 = 有锚点未匹配（smali 结构与预期不符）
"""
import os
import re
import sys

# FrameworkPatch hook 类的全限定名（用于幂等检查）
HOOK_MARKER = "Lcom/android/internal/util/framework/Android;"

# 每个 patch 点：smali 文件相对路径 + 锚点行（正则，需连续匹配）+ 插入行
# 寄存器分析依据 ADAPT_REPORT.md 的真实 smali：
#   - engineGetCertificateChain: v2=leaf, v3=chain[], v4=0；.registers 11
#   - newApplication(Class,Context): p1=context；.registers 3
#   - newApplication(CL,String,Context): p3=context；.registers 5
#   - get(String): p0=key, v0=native返回值；.registers 2
#   - get(String,String): p0=key, p1=def, v0=native返回值；.registers 3
PATCHES = [
    {
        "file": "android/security/keystore2/AndroidKeyStoreSpi.smali",
        "desc": "engineGetCertificateChain",
        # 锚点：aput-object v2, v3, v4（leaf 放入 chain[0]）
        "anchor": [r'^    aput-object v2, v3, v4$'],
        "insert": [
            '    invoke-static {v3}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;',
            '    move-result-object v3',
        ],
    },
    {
        "file": "android/app/Instrumentation.smali",
        "desc": "newApplication(Class, Context) — p1=context",
        # 锚点：attach(p1) 调用行（仅重载1有 p1）
        "anchor": [r'^    invoke-virtual \{v0, p1\}, Landroid/app/Application;->attach\(Landroid/content/Context;\)V$'],
        "insert": [
            '    invoke-static {p1}, Lcom/android/internal/util/framework/Android;->newApplication(Landroid/content/Context;)V',
        ],
    },
    {
        "file": "android/app/Instrumentation.smali",
        "desc": "newApplication(ClassLoader, String, Context) — p3=context",
        # 锚点：attach(p3) 调用行（仅重载2有 p3）
        "anchor": [r'^    invoke-virtual \{v0, p3\}, Landroid/app/Application;->attach\(Landroid/content/Context;\)V$'],
        "insert": [
            '    invoke-static {p3}, Lcom/android/internal/util/framework/Android;->newApplication(Landroid/content/Context;)V',
        ],
    },
    {
        "file": "android/os/SystemProperties.smali",
        "desc": "SystemProperties.get(String) — p0=key, v0=native返回值",
        # 锚点：native_get(String) 调用 + 紧跟的 move-result-object v0
        "anchor": [
            r'^    invoke-static \{p0\}, Landroid/os/SystemProperties;->native_get\(Ljava/lang/String;\)Ljava/lang/String;$',
            r'^    move-result-object v0$',
        ],
        "insert": [
            '    invoke-static {p0, v0}, Lcom/android/internal/util/framework/Android;->systemPropertiesGet(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;',
            '    move-result-object v0',
        ],
    },
    {
        "file": "android/os/SystemProperties.smali",
        "desc": "SystemProperties.get(String, String) — p0=key, p1=def, v0=native返回值",
        # 锚点：native_get(String, String) 调用 + 紧跟的 move-result-object v0
        "anchor": [
            r'^    invoke-static \{p0, p1\}, Landroid/os/SystemProperties;->native_get\(Ljava/lang/String;Ljava/lang/String;\)Ljava/lang/String;$',
            r'^    move-result-object v0$',
        ],
        "insert": [
            '    invoke-static {p0, p1, v0}, Lcom/android/internal/util/framework/Android;->systemPropertiesGet(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;',
            '    move-result-object v0',
        ],
    },
]


def patch_file(filepath, patches):
    """对单个 smali 文件应用所有相关 patch。返回 (patched_count, failed_count)。"""
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    content = "".join(lines)
    # 幂等：已注入过 hook 则整体跳过
    if HOOK_MARKER in content:
        print(f"  [SKIP] 已 patch，跳过: {os.path.basename(filepath)}")
        return 0, 0

    patched = 0
    failed = 0
    # 从后往前插入，避免行号偏移影响后续 patch
    for p in reversed(patches):
        anchor_res = [re.compile(a) for a in p["anchor"]]
        n = len(anchor_res)
        found_at = -1
        for i in range(len(lines) - n + 1):
            ok = True
            for j, rc in enumerate(anchor_res):
                if not rc.match(lines[i + j].rstrip("\n")):
                    ok = False
                    break
            if ok:
                found_at = i
                break
        if found_at < 0:
            print(f"  [FAIL] 锚点未匹配: {p['desc']}")
            failed += 1
            continue
        insert_at = found_at + n  # 在锚点最后一行之后插入
        for k, ins in enumerate(p["insert"]):
            lines.insert(insert_at + k, ins + "\n")
        print(f"  [OK]   {p['desc']}  @ line {found_at + 1}")
        patched += 1

    if patched > 0:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)
    return patched, failed


def main():
    if len(sys.argv) < 3:
        print("用法: python3 patch_smali.py <smali_classes_dir> <smali_classes3_dir>")
        print("  smali_classes_dir   = classes.dex 反编译输出（含 Instrumentation.smali）")
        print("  smali_classes3_dir  = classes3.dex 反编译输出（含 AndroidKeyStoreSpi / SystemProperties）")
        sys.exit(2)

    classes_dir = sys.argv[1]
    classes3_dir = sys.argv[2]

    total_patched = 0
    total_failed = 0

    # 按文件分组 patch
    files_to_patch = {}
    for p in PATCHES:
        files_to_patch.setdefault(p["file"], []).append(p)

    for rel_path, patches in files_to_patch.items():
        # 在两个目录里找文件
        for base in (classes_dir, classes3_dir):
            fp = os.path.join(base, rel_path)
            if os.path.isfile(fp):
                print(f"[PATCH] {fp}")
                pc, fc = patch_file(fp, patches)
                total_patched += pc
                total_failed += fc
                break
        else:
            print(f"[MISS]  未找到 {rel_path}")
            total_failed += len(patches)

    print()
    print(f"=== 结果: {total_patched} 处 patch 成功, {total_failed} 处失败 ===")
    if total_failed > 0:
        print("有锚点未匹配，smali 结构可能与预期不符，请检查 ADAPT_REPORT.md")
        sys.exit(1)
    if total_patched == 0 and total_failed == 0:
        print("（所有文件均已 patch，无操作）")
    sys.exit(0)


if __name__ == "__main__":
    main()

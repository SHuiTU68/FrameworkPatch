# FrameworkPatch smali 适配报告

由 `scripts/extract_smali.sh` 自动生成于 2026-07-31 18:29:58 UTC

## 1. 设备信息

| 项 | 值 |
|---|---|
| 型号 | （未提供） |
| 品牌/设备 | （未提供） / （未提供） |
| Android 版本 | （未提供） (SDK （未提供）) |
| 安全补丁 | （未提供） |
| Build ID | （未提供） |
| 增量 | （未提供） |
| 指纹 | `（未提供）` |

## 2. framework.jar 元信息

| 项 | 值 |
|---|---|
| 大小 | （dex 模式，无整体大小） 字节 |
| MD5 | `（dex 模式，无整体 MD5）` |
| SHA256 | `（dex 模式，无整体 SHA256）` |
| dex 数量 | 6 |

### dex 列表

```
  classes.dex
  classes2.dex
  classes3.dex
  classes4.dex
  classes5.dex
  classes6.dex
```

## 3. hook 点定位结果

| 类 | 所在 dex | 是否找到 |
|---|---|---|
| AndroidKeyStoreSpi | 未找到 | ✗ 未找到 |
| Instrumentation | 未找到 | ✗ 未找到 |
| SystemProperties | 未找到 | ✗ 未找到 |

## 4. 目标方法 smali 片段（核心）

> 下面是从你 framework.jar 反编译出的真实 smali。
> 上游需要这些片段来确定：
> 1. `engineGetCertificateChain` 末尾 leaf cert / chain 数组的寄存器编号
> 2. `newApplication` 各重载里 Context 参数的寄存器编号
> 3. `SystemProperties.get` 两个重载里 `native_get` 返回值的寄存器编号
> 
> 拿到后即可给出**精确到寄存器**的 patch 指令。


### AndroidKeyStoreSpi.engineGetCertificateChain
**未找到该类**（OnePlus/ColorOS 可能用不同的 KeyStore provider，见下方扫描）

### Instrumentation.newApplication
**未找到该类**

### SystemProperties.get
**未找到该类**

### KeyStore provider 类扫描（OEM 差异排查）

```
```

## 5. 重新打包参数

- 反编译命令: `java -jar baksmali.jar d <dex> -o <out_dir>`
- 重新打包命令: `java -jar smali.jar a -a <API_LEVEL> <out_dir> -o <dex>`
- API level 参考: Android 15 = 35, Android 16 = 36

## 6. 下一步

1. 把本报告 (`report/ADAPT_REPORT.md`) 内容发给上游
2. 上游根据第 4 节 smali 片段，给出每个 hook 点的精确 patch 代码
3. 按 README 流程：baksmali → 改 smali → smali a 重打包 → 注入 framework.jar

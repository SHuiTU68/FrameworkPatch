# FKTee-rs

Pure Rust 的 Android keystore2 全局 Hook 模块——通过 ptrace 注入 +
binder ioctl 拦截，让所有应用的 key attestation 证书链由本模块 keybox 签发。
配套 WebUI 提供全局开关、黑名单、prop 属性隐藏。

> 适配 Android 10+（SDK 29+），支持 arm64-v8a / x86_64。
> 需要 Magisk / KernelSU / APatch 提供 root 与 `resetprop`。

## 工作原理

FKTee-rs 有两条实现路径：

### 当前路径：ptrace 注入（已可用）

在运行时注入 `keystore2` 进程，Hook 其 binder 事务：

```
App ──binder──▶ keystore2 ──┬─[正常]──▶ TEE/Keymaster 真实证书
                             └─[Hook]──▶ FKTee-rs 用 keybox 伪造证书链 ◀── App 读到
```

- `injector`：ptrace attach keystore2，远程 dlopen `inject_payload.so`，
  PLT hook `ioctl` 拦截 `BINDER_WRITE_READ` 中的事务。
- `daemon`（fktee）：常驻后端，管理 keybox、响应配置热更新、UID→包名黑名单豁免。
- `certgen`：按 keybox.xml 生成 EC/RSA 证书链（库形式被 daemon 调用）。

> 局限：ptrace 会留下 TracerPid 痕迹，可被反作弊枚举检测。

### 目标路径：KeyMint HAL 替换（方案 A，开发中）

不注入任何进程，把自己注册成 KeyMint HAL service，让 keystore2 主动路由过来：

```
App → keystore2 → binder → [我们的 HAL] ─┬─ attestKey: 用 keybox 伪造证书链
                                           └─ 其余事务: 透传给真 HAL
```

- `hal`（fktee-hal）：用 `rsbinder` + `rsbinder-aidl` 注册为
  `android.hardware.security.keymint.IKeyMintDevice/default`。
- 不碰目标进程内存——无 TracerPid、无 dlopen、无 PLT 修改痕迹。
- 走“代理 + 选择性拦截”：非 attestation 事务透传真 HAL，仅伪造涉证方法。

> 当前 `crates/hal` 为骨架（仅 `getHardwareInfo` + 注册样板），**未接进开机启动**。
> 可用前提：vendoring AOSP 完整 KeyMint AIDL（带 VintfStability 版本/hash）、
> 实现代理转发、放开 sepolicy。详见 [crates/hal/src/main.rs](crates/hal/src/main.rs)
> 顶部架构注释。未完成前 ptrace 路径仍是唯一可用实现。

### 全局 Hook + 黑名单

开启后**所有**走 keystore2 的应用 attestation 都用本模块 keybox 伪造，
无需逐个勾选应用。`deny.list` 中的包名豁免，保留真实硬件证书（用于个别敏感 App）。

黑名单豁免通过 `/data/system/packages.list` 把调用方 UID 反查到包名实现。

## 功能

- **全局 Hook**：一键开关，所有应用 attestation 伪造
- **黑名单**：WebUI 勾选应用豁免（移植自 Tricky 的 app_list 卡片设计）
- **prop 属性隐藏**：`resetprop` 覆盖 verified boot / debug / build 状态
- **USB 调试开关**：配置驱动，即时生效
- **WebUI**：KernelSU WebUI，6 个标签页（全局 / Keybox / 黑名单 / 属性 / USB / 状态）

## 安装

1. 从 [Releases](../../releases) 下载 `FKTee-rs-vX.X.X.zip`。
2. 在 Magisk / KSU / APatch 中刷入模块，重启。
3.（可选）替换真实 keybox：把你的 `keybox.xml` 放到 `/data/adb/Tee-rs/keybox.xml`，
   权限 `0600`。模块自带的 `module/keybox.xml` 是 AOSP 测试模板，无法通过 STRONG。
4. 在 KSU 管理器打开 WebUI 配置。

> 重启后 `service.sh` 自动启动 daemon 与 injector 看门狗，注入 keystore2。

## 配置文件

均在 `/data/adb/Tee-rs/` 下，开机由 `customize.sh` 拷贝模板，之后由 WebUI 维护：

| 文件 | 作用 |
|------|------|
| `injector.toml` | `[hook].enabled` 全局总开关 |
| `deny.list` | 黑名单包名（每行一个，豁免伪造） |
| `keybox.xml` | EC/RSA keybox（私钥，勿提交） |
| `props.conf` | prop 属性隐藏清单 |
| `config.toml` | daemon 后端 / 日志配置 |

### props.conf 格式

```
enabled=1                       # 总开关

# 无条件覆盖（每轮轮询执行，防被系统重置）
ro.boot.verifiedbootstate=green
ro.boot.flash.locked=1

# 条件覆盖：仅当 getprop(key) 含 match 才改（隐藏 recovery 模式，避免误改 normal）
ro.bootmode~recovery=unknown

# 一次性：仅开机执行一次，主循环 5s 轮询跳过
once:sys.boot_completed=0
```

`once:` 与 `~` 可组合。完整默认清单见 [module/props.conf](module/props.conf)。

## 构建

需 Rust + Android NDK + Node：

```bash
# Rust 二进制（arm64-v8a / x86_64）
cargo ndk -t arm64-v8a build --release -p fktee-injector
cargo ndk -t arm64-v8a build --release -p fktee-daemon
cargo ndk -t arm64-v8a build --release -p certgen

# WebUI（输出到 module/webroot/）
cd webui && npm ci && npm run build
```

CI（`.github/workflows/build-fktee.yml`）在推送到 `main` 时自动构建并发布。
注意 payload 是 `libinject_payload.so`（导出 `entry()`），不是 `libcertgen.so`。

## 项目结构

```
crates/
  injector/   # ptrace 注入 + binder ioctl hook（inject + inject_payload.so）— 当前可用
  daemon/     # fktee 常驻后端 + keybox 管理 + 黑名单豁免
  certgen/    # 证书链生成库
  hal/        # KeyMint HAL 替换骨架（方案 A，rsbinder + AIDL）— 开发中
module/       # Magisk 模块（service.sh / customize.sh / 配置模板）
webui/        # KernelSU WebUI（Vite + TS + @material/web）
```

## 许可

AGPL-3.0-or-later。注入器/hook 实现参考了 OhMyKeymint / ForgeStore /
TEESimulator-RS 的思路，WebUI 应用列表卡片设计移植自 Tricky-Addon-Update-Target-List，
在此致谢。

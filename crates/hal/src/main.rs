//! fktee-hal — KeyMint HAL 替换骨架（方案 A：binder 层代理，不注入进程）。
//!
//! # 架构目标
//!
//! 与 ptrace 注入不同，本 crate 把自己注册成 KeyMint HAL service，让
//! keystore2 主动路由过来：
//!
//! ```text
//! App → keystore2 → binder → [我们的 HAL] ─┬─ attestKey: 用 keybox 伪造证书链
//!                                            └─ 其余事务: 透传给真 HAL
//! ```
//!
//! 这样**不碰任何目标进程内存**——无 TracerPid、无 dlopen、无 PLT 修改痕迹。
//! 检测面从“进程被注入”降到“多一个 binder service”（可借 SELinux/hideproc 收窄）。
//!
//! # 实现路径（代理转发，非全量实现）
//!
//! KeyMint 是 `@VintfStability` 接口，不能部分实现——对 generateKey/begin 返回
//! 错误会瘫痪整个 keystore2。因此走“代理 + 选择性拦截”：
//!   1. 设备真 HAL 的 vintf manifest 实例名形如
//!      `android.hardware.security.keymint.IKeyMintDevice/<vendor>`
//!      （vendor 段因 SoC 而异：default / strongbox / keymint-service.* ）。
//!   2. 开机时把真 HAL 改名（vintf manifest 重写 / setprop），或先查到它再
//!      以别名注册。
//!   3. 我们注册成 `.../default`，拿到 keystore2 的全部调用。
//!   4. 非 attestation 事务转发给真 HAL（按别名 wait_for_interface）。
//!   5. 仅 `attestKey`（及 `convertStorageKeyToEphemeral` 等涉证方法）用本模块
//!      keybox 经 certgen 签发伪造证书链返回。
//!   6. 黑名单豁免：binder 调用自带 caller UID/PID，反查 packages.list 命中
//!      deny.list 则直通真 HAL（不伪造）。
//!
//! # 当前状态：骨架
//!
//! 本文件只实现 service 注册样板 + getHardwareInfo，**不接进开机启动**（见
//! service.sh 注释）。可用前提：
//!   - aidl/ 下替换为 AOSP 冻结快照（带 VintfStability 版本/hash）；
//!   - build.rs 补 .version().hash()；
//!   - 实现完整接口（代理转发 + attestation 拦截）；
//!   - sepolicy.rule 放开 HAL 注册/查找权限（见 module/sepolicy.rule）；
//!   - 模块开机脚本启动本 service。
//!
//! 上述未完成前，ptrace 注入路径仍是唯一可用实现，保持不变。
//!
//! # 本地验证（不刷机）
//!
//! `cargo check -p fktee-hal` 跑 build.rs 验证 AIDL 能编译成 Rust 绑定。
//! 真机路由验证：手动 `fktee-hal` 起来后 `service list | grep keymint` 应能看到
//! 我们的实例（仅骨架，keystore2 因版本协商会拒绝，属预期）。

// build.rs 生成：OUT_DIR/keymint.rs（在 crate 根定义 pub mod android {...}）
rsbinder::include_aidl!("keymint");

use rsbinder::hub;
use rsbinder::ProcessState;

use crate::android::hardware::security::keymint::IKeyMintDevice::BnKeyMintDevice;
use crate::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo;

/// 占位 HAL 实现。仅 getHardwareInfo 返回固定值，其余方法待补。
struct KeyMintSkeleton;

impl rsbinder::Interface for KeyMintSkeleton {}

impl IKeyMintDevice for KeyMintSkeleton {
    fn r#getHardwareInfo(&self) -> rsbinder::BinderResult<KeyMintHardwareInfo> {
        // 占位值。真实实现应报 KeyMint 4.0（version=400）以匹配现代 keystore2。
        Ok(KeyMintHardwareInfo {
            keyMintVersion: 400,
            keyMintSecurityLevel: 0, // TRUSTED_ENVIRONMENT
            isHwAttestationSupported: true,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("fktee-hal: starting KeyMint HAL skeleton (NOT functional)");

    // 初始化 binder 进程状态（kernel binder 路径，关闭默认 async feature）。
    ProcessState::init_default()?;
    ProcessState::start_thread_pool();

    // 注册为 default 实例。keystore2 通过 getSecurityLevelService(TRUSTED_ENVIRONMENT)
    // 查找 `android.hardware.security.keymint.IKeyMintDevice/default`。
    //
    // 注意：真机上此注册需要 SELinux 放行（见 sepolicy.rule）且与真 HAL 抢
    // default 实例名——必须先把真 HAL 改名，否则 add_service 会因实例已存在失败。
    let service = BnKeyMintDevice::new_binder(KeyMintSkeleton);
    hub::add_service(
        "android.hardware.security.keymint.IKeyMintDevice/default",
        service.as_binder(),
    )?;
    log::info!("fktee-hal: registered as IKeyMintDevice/default");

    // 加入 binder 线程池处理请求（阻塞至线程池终止）。
    let _ = ProcessState::join_thread_pool();

    Ok(())
}

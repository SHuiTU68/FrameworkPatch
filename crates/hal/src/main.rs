//! fktee-hal — KeyMint HAL 替换实现（方案 A：binder 层代理，不注入进程）。
//!
//! # 架构
//!
//! ```text
//! App → keystore2 → binder → [fktee-hal] ─┬─ generateKey/importKey + attestation:
//!                                            generation 模式：软件生成完整虚拟密钥
//!                                            （keyBlob + 证书链公钥一致），begin/finish
//!                                            用软件密钥签名。参考 TEESimulator `!`。
//!                                          └─ 其余事务: 透传真 HAL
//! ```
//!
//! 不碰任何目标进程内存——无 TracerPid、无 dlopen、无 PLT 修改痕迹。
//!
//! # 部署前提
//!
//! 1. vintf manifest 把真 HAL 实例名改为 `fktee-real`（或 hal.toml 配置的
//!    `real_hal_instance`），让 `default` 实例空出。
//! 2. fktee-hal 抢注 `default`，keystore2 通过 getSecurityLevelService 路由过来。
//! 3. sepolicy.rule 放行 HAL 注册 / binder 调用。
//! 4. service.sh 在 late_start 启动 fktee-hal。
//!
//! # 伪造模式（参考 TEESimulator）
//!
//! - `generation`（默认）：软件生成完整虚拟密钥，keyBlob 与 leaf 公钥一致，
//!   begin/finish 用软件密钥签名。彻底，通过公钥一致性检测。
//! - `leaf_hack`：透传真 HAL keyBlob，仅替换证书链。leaf 公钥 ≠ keyBlob 公钥，
//!   高级检测会失败。

// build.rs 生成：OUT_DIR/keymint.rs
rsbinder::include_aidl!("keymint");

mod caller;
mod config;
mod intercept;
mod keystore;
mod operation;
mod proxy;

use std::sync::Arc;

use rsbinder::hub;
use rsbinder::parcelable::Parcelable;
use rsbinder::{get_calling_uid, ProcessState};

use crate::android::hardware::security::keymint::IKeyMintDevice::{
    BnKeyMintDevice, IKeyMintDevice,
};
use crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult;
use crate::android::hardware::security::keymint::KeyMintHardwareInfo::KeyMintHardwareInfo;
use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::BeginResult::BeginResult;
use crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken;

use crate::config::{ForgeMode, HalConfig};
use crate::intercept::{forge_certificate_chain, forge_key_generation, parse_attestation_request};
use certgen::DeviceInfo;

/// KeyMint HAL 代理实现。
///
/// 持有运行时配置（hook 开关 / 黑名单 / 设备信息 / keybox 字节），
/// 按 caller UID 反查包名决定是否伪造。真 HAL 句柄惰性查找并缓存
/// （见 [`proxy`] 模块）。
struct KeyMintProxy {
    cfg: Arc<parking_lot::RwLock<HalConfig>>,
    /// keybox.xml 字节（启动时一次读入，热重载见 [`KeyMintProxy::reload_keybox`]）。
    keybox_xml: parking_lot::RwLock<Vec<u8>>,
}

impl rsbinder::Interface for KeyMintProxy {}

impl KeyMintProxy {
    fn new(cfg: HalConfig) -> Self {
        let keybox_path = cfg.keybox_path.clone();
        let real_instance = cfg.real_hal_instance.clone();
        let s = Self {
            cfg: Arc::new(parking_lot::RwLock::new(cfg)),
            keybox_xml: parking_lot::RwLock::new(load_keybox(&keybox_path)),
        };
        log::info!(
            "fktee-hal: proxy ready (real_hal={real_instance}, keybox={} bytes)",
            s.keybox_xml.read().len()
        );
        s
    }

    /// 重新加载 keybox + deny.list（收到 SIGHUP 或文件变更时调用）。
    #[allow(dead_code)]
    fn reload(&self) {
        let kb_path = self.cfg.read().keybox_path.clone();
        let mut c = self.cfg.write();
        c.load_deny_list();
        drop(c);
        *self.keybox_xml.write() = load_keybox(&kb_path);
        log::info!("fktee-hal: 配置热重载完成");
    }

    /// 判断当前 binder 调用方是否应被伪造。
    /// `caller_pkg` 为调用方包名（用于日志和 ATTESTATION_APPLICATION_ID 兜底）。
    fn should_forge(&self, caller_uid: u32, caller_pkg: &str) -> bool {
        let cfg = self.cfg.read();
        if !cfg.hook.enabled {
            return false;
        }
        if cfg.hook.deny_packages.is_empty() {
            return true;
        }
        // caller_pkg 已由 caller::packages_for_uid 解析；若为空（packages.list 不可读）
        // 保守不豁免（继续伪造）——黑名单是可选安全网。
        if caller_pkg.is_empty() {
            return true;
        }
        let denied = cfg.hook.deny_packages.iter().any(|p| p == caller_pkg);
        if denied {
            log::debug!("fktee-hal: uid={caller_uid} pkg={caller_pkg} 命中黑名单，透传");
        }
        !denied
    }

    /// 取真 HAL 代理；失败返回 Unknown（generic binder error）。
    fn real_hal(
        &self,
    ) -> rsbinder::BinderResult<&'static rsbinder::Strong<dyn IKeyMintDevice>> {
        let instance = self.cfg.read().real_hal_instance.clone();
        proxy::get_real_hal(&instance)
            .ok_or_else(|| rsbinder::StatusCode::Unknown.into())
    }

    /// 构造 certgen DeviceInfo（从 hal.toml device 段 + 系统 prop 兜底）。
    ///
    /// **auto 语义**：`[device]` 段中值为 `0` 或 `-1` 的字段表示"自动获取"，
    /// 运行时从系统属性读取真实值；值 `>0` 表示用户自定义，原样使用。
    /// `security_level` 例外——它不被 auto 覆盖（0 时由 certgen 兜底为 TEE=1），
    /// 因为 attestation 安全级别应反映伪造意图而非真机硬件。
    fn device_info(&self) -> DeviceInfo {
        let c = self.cfg.read();
        let d = &c.device;
        DeviceInfo {
            android_version: resolve_or(d.android_version, || {
                getprop("ro.build.version.release")
                    .and_then(|s| s.split('.').next().and_then(|n| n.parse::<i32>().ok()))
                    .unwrap_or(0)
            }),
            os_version: resolve_or(d.os_version, || {
                // 优先用 ro.build.version.os_version（部分设备有），否则按 SDK 推算。
                getprop("ro.build.version.os_version")
                    .and_then(|s| s.parse::<i32>().ok())
                    .or_else(|| {
                        getprop("ro.build.version.sdk")
                            .and_then(|s| s.parse::<i32>().ok())
                            .map(|sdk| {
                                // Android 14=340000, 15=350000 等（AOSP 版本号规则）
                                let major = sdk / 100;
                                major * 10000 + sdk
                            })
                    })
                    .unwrap_or(0)
            }),
            os_patch_level: resolve_or(d.os_patch_level, || {
                parse_patch_date(getprop("ro.build.version.security_patch").as_deref())
            }),
            vendor_patch_level: resolve_or(d.vendor_patch_level, || {
                parse_patch_date(getprop("ro.vendor.build.security_patch").as_deref())
            }),
            boot_patch_level: resolve_or(d.boot_patch_level, || {
                // 无独立 boot patch 属性，回退到 security_patch
                parse_patch_date(getprop("ro.build.version.security_patch").as_deref())
            }),
            // keymaster/attestation_version 保持 0 走 certgen 兜底（300），
            // 用户填具体值则原样用。
            keymaster_version: d.keymaster_version,
            attestation_version: d.attestation_version,
            security_level: d.security_level,
            creation_datetime: 0, // certgen 用当前时间兜底
            boot_key: Vec::new(), // certgen 用全零兜底
            boot_hash: Vec::new(),
        }
    }

    /// 处理 generateKey/importKey：含 attestation challenge 且未豁免时伪造证书链。
    ///
    /// 按 `forge_mode` 分发：
    /// - `generation`：软件生成完整虚拟密钥（keyBlob + 证书链公钥一致）。失败
    ///   时 fallback 到 leaf_hack，再失败透传真 HAL。
    /// - `leaf_hack`：透传真 HAL keyBlob，仅替换证书链。
    ///
    /// 返回值：原样透传、证书链替换后、或软件生成的 KeyCreationResult。
    fn handle_key_creation(
        &self,
        params: &[KeyParameter],
        real: KeyCreationResult,
    ) -> KeyCreationResult {
        let uid = get_calling_uid();
        let pkgs = caller::packages_for_uid(uid);
        let caller_pkg = pkgs.first().cloned().unwrap_or_default();

        if !self.should_forge(uid, &caller_pkg) {
            return real;
        }

        let Some(req) = parse_attestation_request(params, &caller_pkg) else {
            // 无 attestation challenge，原样透传真 HAL 结果
            return real;
        };

        let keybox = self.keybox_xml.read().clone();
        if keybox.is_empty() {
            log::warn!("fktee-hal: keybox 为空，无法伪造，透传真 HAL 证书链");
            return real;
        }

        let device = self.device_info();
        let mode = self.cfg.read().hook.forge_mode.resolved();

        match mode {
            ForgeMode::Generation => {
                // generation 模式：软件生成完整虚拟密钥。失败 fallback leaf_hack。
                match forge_key_generation(params, &req, &keybox, &device) {
                    Ok(result) => result,
                    Err(e) => {
                        log::warn!(
                            "fktee-hal: generation 失败，fallback leaf_hack: {e:?}"
                        );
                        forge_certificate_chain(real, &req, &keybox, &device)
                    }
                }
            }
            ForgeMode::LeafHack => forge_certificate_chain(real, &req, &keybox, &device),
            ForgeMode::Auto => {
                // resolved() 已把 Auto → Generation，这里不可达。
                forge_certificate_chain(real, &req, &keybox, &device)
            }
        }
    }
}

impl IKeyMintDevice for KeyMintProxy {
    fn r#getHardwareInfo(&self) -> rsbinder::BinderResult<KeyMintHardwareInfo> {
        // 透传真 HAL（保留真实版本号 / 安全级别），keystore2 据此选择实例。
        // 不需要伪造——硬件信息不暴露 attestation。
        self.real_hal()?.r#getHardwareInfo()
    }

    fn r#addRngEntropy(&self, data: &[u8]) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#addRngEntropy(data)
    }

    fn r#generateKey(
        &self,
        key_params: &[KeyParameter],
        attestation_key: Option<&crate::android::hardware::security::keymint::AttestationKey::AttestationKey>,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        let real = self.real_hal()?.r#generateKey(key_params, attestation_key)?;
        Ok(self.handle_key_creation(key_params, real))
    }

    fn r#importKey(
        &self,
        key_params: &[KeyParameter],
        key_format: crate::android::hardware::security::keymint::KeyFormat::KeyFormat,
        key_data: &[u8],
        attestation_key: Option<&crate::android::hardware::security::keymint::AttestationKey::AttestationKey>,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        let real = self
            .real_hal()?
            .r#importKey(key_params, key_format, key_data, attestation_key)?;
        Ok(self.handle_key_creation(key_params, real))
    }

    fn r#importWrappedKey(
        &self,
        wrapped_key_data: &[u8],
        wrapping_key_blob: &[u8],
        masking_key: &[u8],
        unwrapping_params: &[KeyParameter],
        password_sid: i64,
        biometric_sid: i64,
    ) -> rsbinder::BinderResult<KeyCreationResult> {
        // importWrappedKey 一般不触发 attestation（wrapped key 自带证书链），
        // 但仍走 handle_key_creation 以防万一。
        let real = self.real_hal()?.r#importWrappedKey(
            wrapped_key_data,
            wrapping_key_blob,
            masking_key,
            unwrapping_params,
            password_sid,
            biometric_sid,
        )?;
        Ok(self.handle_key_creation(unwrapping_params, real))
    }

    fn r#upgradeKey(
        &self,
        key_blob_to_upgrade: &[u8],
        upgrade_params: &[KeyParameter],
    ) -> rsbinder::BinderResult<Vec<u8>> {
        // 软件 keyBlob 无需升级（不绑定 OS 版本），原样返回。
        if keystore::is_software_blob(key_blob_to_upgrade) {
            return Ok(key_blob_to_upgrade.to_vec());
        }
        self.real_hal()?.r#upgradeKey(key_blob_to_upgrade, upgrade_params)
    }

    fn r#deleteAllKeys(&self) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#deleteAllKeys()
    }

    fn r#destroyAttestationIds(&self) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#destroyAttestationIds()
    }

    fn r#begin(
        &self,
        purpose: crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose,
        key_blob: &[u8],
        params: &[KeyParameter],
        auth_token: Option<&crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken>,
    ) -> rsbinder::BinderResult<BeginResult>
    {
        // generation 模式：软件 keyBlob 不回调真 HAL，直接构造 SoftwareOperation。
        if keystore::is_software_blob(key_blob) {
            let kp = keystore::load(key_blob).ok_or_else(|| {
                log::warn!("fktee-hal: 软件 keyBlob 加载失败（可能进程重启后失效）");
                rsbinder::Status::from(rsbinder::StatusCode::BadValue)
            })?;
            let op = operation::SoftwareOperation::new(kp);
            log::debug!(
                "fktee-hal: begin 软件 keyBlob ({}B) → SoftwareOperation",
                key_blob.len()
            );
            return Ok(BeginResult {
                r#challenge: 0,
                r#params: params.to_vec(),
                r#operation: Some(op.into_strong()),
            });
        }
        // 真硬件 keyBlob：透传真 HAL
        self.real_hal()?.r#begin(purpose, key_blob, params, auth_token)
    }

    fn r#deleteKey(&self, key_blob: &[u8]) -> rsbinder::BinderResult<()> {
        // 软件 keyBlob：从内存表移除；真 keyBlob：透传真 HAL。
        if keystore::is_software_blob(key_blob) {
            keystore::remove(key_blob);
            return Ok(());
        }
        self.real_hal()?.r#deleteKey(key_blob)
    }

    fn r#deviceLocked(
        &self,
        password_only: bool,
        timestamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#deviceLocked(password_only, timestamp_token)
    }

    fn r#earlyBootEnded(&self) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#earlyBootEnded()
    }

    fn r#convertStorageKeyToEphemeral(&self, storage_key_blob: &[u8]) -> rsbinder::BinderResult<Vec<u8>> {
        self.real_hal()?.r#convertStorageKeyToEphemeral(storage_key_blob)
    }

    fn r#getKeyCharacteristics(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        app_data: &[u8],
    ) -> rsbinder::BinderResult<Vec<crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics>>
    {
        // 软件 keyBlob：keystore2 正常路径下不会调到这里（characteristics 已在
        // generateKey 返回时缓存）；若被调到，返回空（保守）。
        if keystore::is_software_blob(key_blob) {
            return Ok(Vec::new());
        }
        self.real_hal()?.r#getKeyCharacteristics(key_blob, app_id, app_data)
    }

    fn r#getRootOfTrustChallenge(&self) -> rsbinder::BinderResult<[u8; 16]> {
        self.real_hal()?.r#getRootOfTrustChallenge()
    }

    fn r#getRootOfTrust(&self, challenge: &[u8; 16]) -> rsbinder::BinderResult<Vec<u8>> {
        self.real_hal()?.r#getRootOfTrust(challenge)
    }

    fn r#sendRootOfTrust(&self, root_of_trust: &[u8]) -> rsbinder::BinderResult<()> {
        self.real_hal()?.r#sendRootOfTrust(root_of_trust)
    }
}

/// 读取 keybox.xml 字节。文件缺失返回空 Vec（调用方走透传兜底）。
fn load_keybox(path: &std::path::Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => {
            log::info!("fktee-hal: keybox 加载 {} 字节", bytes.len());
            bytes
        }
        Err(e) => {
            log::warn!("fktee-hal: keybox 读取失败 ({}): {e}", path.display());
            Vec::new()
        }
    }
}

/// 读取 Android 系统属性（`getprop`）。非 Android 环境返回 `None`。
fn getprop(name: &str) -> Option<String> {
    let output = std::process::Command::new("getprop")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// `val > 0` → `val`（用户自定义）；否则（0 / -1 = auto）调用 `fallback` 取真实值。
fn resolve_or(val: i32, fallback: impl FnOnce() -> i32) -> i32 {
    if val > 0 {
        val
    } else {
        let v = fallback();
        if v == 0 {
            // 真实值也读不到：patch_level 用 -1（attestation 扩展中-1=不报告），
            // 其余字段保持 0 让 certgen 兜底。
            -1
        } else {
            v
        }
    }
}

/// 把 `YYYY-MM-DD` 格式日期解析为 `YYYYMMDD` 整数（如 2025-03-01 → 20250301）。
/// 输入为空或格式不符返回 0（调用方再走 -1 兜底）。
fn parse_patch_date(s: Option<&str>) -> i32 {
    let Some(s) = s else { return 0 };
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 8 {
        digits[..8].parse::<i32>().unwrap_or(0)
    } else {
        0
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    log::info!("fktee-hal: starting KeyMint HAL proxy (方案 A)");

    // 配置：/data/adb/Tee-rs/hal.toml（缺失走默认）。
    let cfg_path = std::path::Path::new("/data/adb/Tee-rs/hal.toml");
    let mut cfg = HalConfig::load(cfg_path);
    cfg.load_deny_list();

    // 初始化 binder 进程状态。
    ProcessState::init_default()?;
    ProcessState::start_thread_pool();

    let proxy = KeyMintProxy::new(cfg);

    // 注册为 default 实例。真 HAL 必须已被 vintf manifest 改名为 real_hal_instance，
    // 否则 add_service 会因 default 已占用失败。
    let service = BnKeyMintDevice::new_binder(proxy);
    hub::add_service(
        "android.hardware.security.keymint.IKeyMintDevice/default",
        service.as_binder(),
    )?;
    log::info!("fktee-hal: registered as IKeyMintDevice/default");

    // 加入 binder 线程池处理请求（阻塞至线程池终止）。
    let _ = ProcessState::join_thread_pool();

    Ok(())
}

// 静默引入 Parcelable trait 以避免 unused import 警告（KeyCreationResult 等结构体
// 在 forge_certificate_chain 中按字段构造，未直接调用 Parcelable 方法，但 trait
// 必须在作用域内以使用其实现的 Default）。
#[allow(dead_code)]
fn _ensure_parcelable_in_scope<T: Parcelable>(_: &T) {}

// 编译期断言：TimeStampToken 在作用域（用于 deviceLocked 签名）。
#[allow(dead_code)]
const _: fn() = || {
    let _: TimeStampToken;
};

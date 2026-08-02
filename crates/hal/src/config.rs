//! fktee-hal 配置（`hal.toml`）。
//!
//! 与 daemon 的 `injector.toml` 共享黑名单语义，但只读 HAL 自身需要的字段：
//! - `real_hal_instance`：真 HAL 被 vintf manifest 重命名后的实例名
//!   （fktee-hal 抢占 `default`，按此名 wait_for_interface 拿真 HAL 代理）。
//! - `hook.enabled` / `hook.deny_packages`：全局开关 + 黑名单（与 injector 同义）。
//! - `keybox_path`：keybox.xml 路径（默认 `/data/adb/Tee-rs/keybox.xml`）。
//! - `deny_list_path`：黑名单文件路径（默认 `/data/adb/Tee-rs/deny.list`）。
//! - `device`：DeviceInfo 默认值（缺失字段由 certgen 兜底）。
//!
//! 文件缺失 / 解析失败时回退默认值，不抛错——避免 HAL 启动失败卡死 keystore2。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// HAL 顶层配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalConfig {
    /// 真 HAL 被 vintf manifest 重命名后的实例名（不含接口前缀）。
    /// 例：`fktee-real` → wait_for_interface("android.hardware.security.keymint.IKeyMintDevice/fktee-real")
    #[serde(default = "default_real_hal_instance")]
    pub real_hal_instance: String,

    #[serde(default)]
    pub hook: HookConfig,

    #[serde(default = "default_keybox_path")]
    pub keybox_path: PathBuf,

    #[serde(default = "default_deny_list_path")]
    pub deny_list_path: PathBuf,

    #[serde(default)]
    pub device: DeviceDefaults,
}

fn default_real_hal_instance() -> String {
    "fktee-real".into()
}

fn default_keybox_path() -> PathBuf {
    PathBuf::from("/data/adb/Tee-rs/keybox.xml")
}

fn default_deny_list_path() -> PathBuf {
    PathBuf::from("/data/adb/Tee-rs/deny.list")
}

/// 全局 hook 开关 + 黑名单（语义与 daemon `HookConfig` 一致）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// 全局总开关：`false` 时所有事务透传真 HAL，不伪造。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 黑名单：列出的包名走真 HAL（不伪造）。运行时被 `deny_list_path` 文件覆盖。
    #[serde(default)]
    pub deny_packages: Vec<String>,
    /// 伪造模式（参考 TEESimulator 的 `!` / `?` 概念）：
    /// - `auto`        : 自动选择（当前等价 generation）。
    /// - `generation`  : 软件生成完整虚拟密钥，keyBlob 与 leaf 证书公钥一致
    ///                    （对应 TEESimulator `!` Force Generation Mode）。彻底但需
    ///                    拦截 begin()/finish() 用软件密钥签名。
    /// - `leaf_hack`   : 透传真 HAL keyBlob，仅替换证书链（leaf 公钥 ≠ keyBlob 公钥，
    ///                    高级检测会失败）。对应 TEESimulator `?` Force Leaf Hacking。
    #[serde(default = "default_forge_mode")]
    pub forge_mode: ForgeMode,
}

/// 伪造模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForgeMode {
    /// 自动选择（当前等价 generation）。
    Auto,
    /// 软件生成完整虚拟密钥（keyBlob + leaf 公钥一致）。
    Generation,
    /// 仅替换证书链（leaf 公钥 ≠ keyBlob 公钥）。
    LeafHack,
}

impl Default for ForgeMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl ForgeMode {
    /// `auto` 在当前实现中等价 `generation`（更彻底，优先选它）。
    pub fn resolved(self) -> Self {
        match self {
            Self::Auto => Self::Generation,
            other => other,
        }
    }
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_packages: Vec::new(),
            forge_mode: ForgeMode::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_forge_mode() -> ForgeMode {
    ForgeMode::default()
}

/// DeviceInfo 默认值（对应 certgen::DeviceInfo）。
/// 未填字段（0 / 空）由 certgen 用合理默认兜底。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceDefaults {
    #[serde(default)]
    pub android_version: i32,
    #[serde(default)]
    pub os_version: i32,
    #[serde(default)]
    pub os_patch_level: i32,
    #[serde(default)]
    pub vendor_patch_level: i32,
    #[serde(default)]
    pub boot_patch_level: i32,
    #[serde(default)]
    pub keymaster_version: i32,
    #[serde(default)]
    pub attestation_version: i32,
    #[serde(default)]
    pub security_level: i32,
}

impl Default for HalConfig {
    fn default() -> Self {
        Self {
            real_hal_instance: default_real_hal_instance(),
            hook: HookConfig::default(),
            keybox_path: default_keybox_path(),
            deny_list_path: default_deny_list_path(),
            device: DeviceDefaults::default(),
        }
    }
}

impl HalConfig {
    /// 加载 `hal.toml`。文件缺失或解析失败 → 返回默认值（不抛错）。
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            log::warn!("hal 配置不存在，使用默认: {}", path.display());
            return Self::default();
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            log::warn!("hal 配置读取失败，使用默认: {}", path.display());
            return Self::default();
        };
        match toml::from_str::<Self>(&content) {
            Ok(cfg) => {
                log::info!(
                    "hal 配置加载: real={} enabled={} deny={}",
                    cfg.real_hal_instance,
                    cfg.hook.enabled,
                    cfg.hook.deny_packages.len()
                );
                cfg
            }
            Err(e) => {
                log::error!("hal 配置解析失败，使用默认: {e}");
                Self::default()
            }
        }
    }

    /// 从 `deny.list` 文件覆盖黑名单（每行一个包名，`#` 与空行跳过）。
    pub fn load_deny_list(&mut self) {
        let Ok(content) = std::fs::read_to_string(&self.deny_list_path) else {
            return;
        };
        let pkgs: Vec<String> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
        if !pkgs.is_empty() {
            self.hook.deny_packages = pkgs;
        }
        log::info!("hal 黑名单加载: {} 个包", self.hook.deny_packages.len());
    }
}

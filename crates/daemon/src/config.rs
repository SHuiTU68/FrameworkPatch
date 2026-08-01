//! daemon 的配置管理（`config.toml`）。
//!
//! 参考 OhMyKeymint 的 config.rs 设计：
//! - [`DaemonConfig`]：daemon 自身配置（后端模式、verified boot 伪装、密钥种子、日志）。
//! - [`InjectorConfig`]：注入器 hook 配置（全局开关 + 各事务拦截开关）。
//!
//! 注意：`InjectorConfig` 在此镜像了 `crates/injector/src/config.rs` 的结构。
//! 由于 injector crate 当前仅以 cdylib 形式提供（其 `config.rs` 属于 bin），
//! daemon 无法直接复用，故在此独立定义一份等价实现，保持 main.rs / server.rs
//! 通过 `crate::config::InjectorConfig` 访问。
//!
//! **全局 hook 模型**：不再按应用白名单过滤，所有走 keystore2 的 attestation
//! 请求一律用 keybox 伪造。`[hook].enabled` 是唯一总开关。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ===================== daemon 自身配置 =====================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub backend: BackendConfig,
    pub trust: TrustConfig,
    #[serde(default)]
    pub crypto: CryptoConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// 后端模式：`"injector"` | `"hal"`。
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustConfig {
    /// verified boot 状态：`"green"` | `"yellow"` | `"orange"` | `"red"`。
    pub verified_boot_state: String,
    /// 设备是否 locked。
    pub device_locked: bool,
    /// `"auto"` | `"random"` | `"<hex>"`。
    pub vb_key: String,
    /// `"auto"` | `"random"` | `"<hex>"`。
    pub vb_hash: String,
    /// `"auto"` | `"latest"` | `"YYYY-MM-DD"`。
    pub security_patch: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// root KEK 种子（hex，空表示运行时自动生成）。
    pub root_kek_seed: String,
    /// KAK 种子（hex，空表示运行时自动生成）。
    pub kak_seed: String,
    /// shared secret 种子（hex，空表示运行时自动生成）。
    pub shared_secret_seed: String,
    /// shared secret nonce（hex，空表示运行时自动生成）。
    pub shared_secret_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// `"debug"` | `"info"` | `"warn"` | `"error"`。
    pub level: String,
    /// 是否输出到 `/dev/kmsg`（内核日志，便于早期调试）。
    pub to_kmsg: bool,
    /// 是否打印详细日志。
    pub verbose: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            backend: BackendConfig {
                mode: "injector".into(),
            },
            trust: TrustConfig {
                verified_boot_state: "green".into(),
                device_locked: true,
                vb_key: "auto".into(),
                vb_hash: "auto".into(),
                security_patch: "auto".into(),
            },
            crypto: CryptoConfig::default(),
            log: LogConfig {
                level: "info".into(),
                to_kmsg: false,
                verbose: false,
            },
        }
    }
}

impl DaemonConfig {
    /// 加载配置文件。
    ///
    /// - 文件不存在：返回默认值。
    /// - 文件存在且解析成功：返回解析结果。
    /// - 文件存在但解析失败：备份原文件（追加 `.bak`）后返回默认值，
    ///   避免损坏的配置卡死 daemon。
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            log::warn!("配置文件不存在，使用默认配置: {}", path.display());
            return Ok(Self::default());
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                log::error!("读取配置文件失败，使用默认配置: {e}");
                return Ok(Self::default());
            }
        };

        match toml::from_str::<Self>(&content) {
            Ok(cfg) => {
                log::info!("配置加载完成: backend={}", cfg.backend.mode);
                Ok(cfg)
            }
            Err(e) => {
                log::error!("配置解析失败，备份原文件并使用默认配置: {e}");
                let mut backup = path.as_os_str().to_owned();
                backup.push(".bak");
                if let Err(be) = std::fs::copy(path, &backup) {
                    log::warn!("备份配置文件失败: {be}");
                } else {
                    log::info!("已备份原配置到: {}", Path::new(&backup).display());
                }
                Ok(Self::default())
            }
        }
    }

    /// 解析 verified boot key。
    ///
    /// - `"auto"`：尝试从系统属性读取 `ro.boot.vbmeta.digest`，失败则回退到全零。
    /// - `"random"`：从 `/dev/urandom` 读取 32 字节并 hex 编码。
    /// - 其它：视为 hex 原样返回。
    pub fn resolve_vb_key(&self) -> String {
        match self.trust.vb_key.trim() {
            "auto" => getprop("ro.boot.vbmeta.digest").unwrap_or_else(|| "00".repeat(32)),
            "random" => random_hex(32).unwrap_or_else(|| "00".repeat(32)),
            hex => hex.to_string(),
        }
    }

    /// 解析 verified boot hash。
    ///
    /// - `"auto"`：尝试从系统属性读取 `ro.boot.vbmeta.hash`，失败则回退到全零。
    /// - `"random"`：从 `/dev/urandom` 读取 32 字节并 hex 编码。
    /// - 其它：视为 hex 原样返回。
    pub fn resolve_vb_hash(&self) -> String {
        match self.trust.vb_hash.trim() {
            "auto" => getprop("ro.boot.vbmeta.hash")
                .or_else(|| getprop("ro.boot.vbmeta.digest"))
                .unwrap_or_else(|| "00".repeat(32)),
            "random" => random_hex(32).unwrap_or_else(|| "00".repeat(32)),
            hex => hex.to_string(),
        }
    }

    /// 解析 security patch 日期。
    ///
    /// - `"auto"` / `"latest"`：读取 `ro.build.version.security_patch`，失败回退到默认值。
    /// - 其它（如 `"2024-09-05"`）：原样返回。
    pub fn resolve_security_patch(&self) -> String {
        match self.trust.security_patch.trim() {
            "auto" | "latest" => {
                getprop("ro.build.version.security_patch").unwrap_or_else(|| "2024-09-05".into())
            }
            s => s.to_string(),
        }
    }
}

// ===================== 注入器配置（镜像 injector crate） =====================

/// injector 配置（全局 hook + 黑名单模型）。
///
/// 与 `crates/injector/src/config.rs` 等价。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectorConfig {
    #[serde(default)]
    pub hook: HookConfig,
    #[serde(default)]
    pub intercept: InterceptConfig,
}

/// 全局 hook 开关 + 黑名单。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// 全局总开关：`true` = 所有应用走 keystore2 的 attestation 都用 keybox 伪造。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 黑名单：列出的包名不会被伪造（透传原始 attestation）。
    /// 可在 toml 声明，运行时也会被 `deny.list` 文件覆盖。
    #[serde(default)]
    pub deny_packages: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            deny_packages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    #[serde(default = "default_true")]
    pub get_key_entry: bool,
    #[serde(default = "default_true")]
    pub generate_key: bool,
    #[serde(default = "default_true")]
    pub import_key: bool,
    #[serde(default = "default_true")]
    pub create_operation: bool,
    #[serde(default = "default_true")]
    pub delete_key: bool,
    #[serde(default = "default_true")]
    pub list_entries: bool,
    #[serde(default = "default_true")]
    pub grant: bool,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            get_key_entry: true,
            generate_key: true,
            import_key: true,
            create_operation: true,
            delete_key: true,
            list_entries: true,
            grant: true,
        }
    }
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            hook: HookConfig::default(),
            intercept: InterceptConfig::default(),
        }
    }
}

impl InjectorConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            log::warn!("配置文件不存在，使用默认配置: {}", path.display());
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&content)?;
        log::info!(
            "配置加载完成: hook.enabled={} deny={} (全局模式，所有应用生效)",
            config.hook.enabled,
            config.hook.deny_packages.len()
        );
        Ok(config)
    }

    /// 从 `deny.list` 文件覆盖加载黑名单（每行一个包名，跳过空行与 `#` 注释）。
    pub fn load_deny_list(&mut self, path: &Path) {
        let Ok(content) = std::fs::read_to_string(path) else {
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
        log::info!("黑名单加载: {} 个包", self.hook.deny_packages.len());
    }

    /// hook 是否对指定包名生效（全局开关开 + 包名不在黑名单）。
    pub fn should_forge(&self, package: &str) -> bool {
        self.hook.enabled && !self.hook.deny_packages.iter().any(|p| p == package)
    }

    /// hook 是否生效（不考虑黑名单）。
    pub fn is_active(&self) -> bool {
        self.hook.enabled
    }
}

// ===================== 系统属性 / 随机数辅助 =====================

/// 读取 Android 系统属性（`getprop`）。
///
/// 在非 Android 环境（如 CI 构建机）调用会返回 `None`，调用方需自行回退。
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

/// 从 `/dev/urandom` 读取 `nbytes` 字节并返回 hex 字符串。
fn random_hex(nbytes: usize) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    let mut buf = vec![0u8; nbytes];
    f.read_exact(&mut buf).ok()?;
    Some(buf.iter().map(|b| format!("{b:02x}")).collect())
}

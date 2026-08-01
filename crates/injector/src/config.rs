//! injector.toml 配置解析
//!
//! **全局 hook + 黑名单模型**：FKTee-rs 注入到 keystore2 后，所有走 keystore2 的
//! attestation 请求一律用本模块的 keybox 签发伪造证书链——不再按应用白名单
//! 过滤。黑名单 `[hook].deny_packages`（或独立的 `deny.list` 文件）中列出的
//! 应用包名会被豁免（透传原始 attestation），用于保留个别敏感应用的真实证书。
//!
//! 黑名单优先级：`deny.list` 文件（每行一个包名）覆盖 toml 里的
//! `deny_packages`，便于 WebUI 直接编辑单个文件而无需重写整个 toml。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// injector 配置（全局）。
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
    /// 全局总开关。
    /// - `true`：所有应用的 keystore2 attestation 都用 keybox 伪造。
    /// - `false`：hook 不生效，全部放行（透传原始事务）。
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

/// 各事务拦截开关（默认全开）。
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
    /// 文件不存在则保留 toml 中已有的 `deny_packages`。
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = InjectorConfig::default();
        assert!(cfg.hook.enabled, "默认应为全局启用");
        assert!(cfg.is_active());
        assert!(cfg.should_forge("com.any.app"));
    }

    #[test]
    fn test_disabled() {
        let mut cfg = InjectorConfig::default();
        cfg.hook.enabled = false;
        assert!(!cfg.is_active());
        assert!(!cfg.should_forge("com.any.app"));
    }

    #[test]
    fn test_deny_list() {
        let mut cfg = InjectorConfig::default();
        cfg.hook.deny_packages = vec!["com.bank.app".into()];
        assert!(!cfg.should_forge("com.bank.app"));
        assert!(cfg.should_forge("com.other.app"));
    }

    #[test]
    fn test_parse_global() {
        // 部分字段省略应回退到默认值（true），不能解析失败
        let toml = r#"
[hook]
enabled = true
[intercept]
get_key_entry = false
"#;
        let cfg: InjectorConfig = toml::from_str(toml).unwrap();
        assert!(cfg.is_active());
        assert!(!cfg.intercept.get_key_entry);
        assert!(cfg.intercept.generate_key);
        assert!(cfg.intercept.create_operation);
    }

    #[test]
    fn test_parse_deny_packages() {
        let toml = r#"
[hook]
enabled = true
deny_packages = ["com.a", "com.b"]
"#;
        let cfg: InjectorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.hook.deny_packages.len(), 2);
        assert!(!cfg.should_forge("com.a"));
    }
}

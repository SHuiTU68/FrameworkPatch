//! injector.toml 配置解析
//!
//! **白名单模型**：FKTee-rs 注入到 keystore2 后，仅对 `allow_packages`（或独立的
//! `allow.list` 文件）中列出的应用包名进行 attestation 伪造。未列出的应用
//! 透传原始 attestation，保持真实硬件证书。
//!
//! 白名单优先级：`allow.list` 文件（每行一个包名）覆盖 toml 里的
//! `allow_packages`，便于 WebUI 直接编辑单个文件而无需重写整个 toml。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// injector 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectorConfig {
    #[serde(default)]
    pub hook: HookConfig,
    #[serde(default)]
    pub intercept: InterceptConfig,
}

/// 白名单 hook 配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// 总开关。
    /// - `true`：对 `allow_packages` 中的应用进行 attestation 伪造。
    /// - `false`：hook 不生效，全部放行（透传原始事务）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 白名单：仅对列出的包名进行伪造。空列表 = 不伪造任何应用。
    /// 可在 toml 声明，运行时也会被 `allow.list` 文件覆盖。
    #[serde(default)]
    pub allow_packages: Vec<String>,
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
            allow_packages: Vec::new(),
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
        let config: Self = toml::from_str(&content)?;
        log::info!(
            "配置加载完成: hook.enabled={} allow={} (白名单模式)",
            config.hook.enabled,
            config.hook.allow_packages.len()
        );
        Ok(config)
    }

    /// 从 `allow.list` 文件覆盖加载白名单（每行一个包名，跳过空行与 `#` 注释）。
    /// 文件不存在则保留 toml 中已有的 `allow_packages`。
    pub fn load_allow_list(&mut self, path: &Path) {
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
            self.hook.allow_packages = pkgs;
        }
        log::info!("白名单加载: {} 个包", self.hook.allow_packages.len());
    }

    /// hook 是否对指定包名生效（白名单模式：仅在 allow_packages 中的包被伪造）。
    pub fn should_forge(&self, package: &str) -> bool {
        self.hook.enabled && self.hook.allow_packages.iter().any(|p| p == package)
    }

    /// hook 是否生效（不考虑白名单）。
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
        assert!(cfg.hook.enabled, "默认应启用");
        assert!(cfg.is_active());
        // 空白名单 = 不伪造任何应用
        assert!(!cfg.should_forge("com.any.app"));
    }

    #[test]
    fn test_disabled() {
        let mut cfg = InjectorConfig::default();
        cfg.hook.enabled = false;
        assert!(!cfg.is_active());
        assert!(!cfg.should_forge("com.any.app"));
    }

    #[test]
    fn test_allow_list() {
        let mut cfg = InjectorConfig::default();
        cfg.hook.allow_packages = vec!["com.target.app".into()];
        assert!(cfg.should_forge("com.target.app"));
        assert!(!cfg.should_forge("com.other.app"));
    }

    #[test]
    fn test_empty_allow_list() {
        let cfg = InjectorConfig::default();
        // 空白名单时，即使 enabled=true，也不伪造任何应用
        assert!(!cfg.should_forge("com.any.app"));
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
    fn test_parse_allow_packages() {
        let toml = r#"
[hook]
enabled = true
allow_packages = ["com.a", "com.b"]
"#;
        let cfg: InjectorConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.hook.allow_packages.len(), 2);
        assert!(cfg.should_forge("com.a"));
        assert!(!cfg.should_forge("com.c"));
    }
}
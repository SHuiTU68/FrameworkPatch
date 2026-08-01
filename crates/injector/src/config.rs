//! injector.toml 配置解析

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectorConfig {
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub enabled: bool,
    pub allow_unknown_package: bool,
    pub block_android_package: bool,
    pub scoop: Vec<String>,
    pub deny_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptConfig {
    pub get_key_entry: bool,
    pub generate_key: bool,
    pub import_key: bool,
    pub create_operation: bool,
    pub delete_key: bool,
    pub list_entries: bool,
    pub grant: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            filter: FilterConfig {
                enabled: true,
                allow_unknown_package: false,
                block_android_package: true,
                scoop: vec![
                    "io.github.vvb2060.keyattestation".into(),
                    "com.google.android.gsf".into(),
                    "com.google.android.gms".into(),
                    "com.android.vending".into(),
                    "com.eltavine.duckdetector".into(),
                ],
                deny_packages: vec![],
            },
            intercept: InterceptConfig {
                get_key_entry: true,
                generate_key: true,
                import_key: true,
                create_operation: true,
                delete_key: true,
                list_entries: true,
                grant: true,
            },
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
        log::info!("配置加载完成: scoop={} 个包", config.filter.scoop.len());
        Ok(config)
    }

    /// 检查包名是否在 target 白名单中
    pub fn is_target(&self, package: &str) -> bool {
        if !self.filter.enabled {
            return true;
        }

        if self.filter.block_android_package && package.starts_with("android") {
            return false;
        }

        if self.filter.deny_packages.iter().any(|p| p == package) {
            return false;
        }

        self.filter.scoop.iter().any(|p| p == package)
    }

    /// 获取 scoop 集合（用于快速查找）
    pub fn scoop_set(&self) -> HashSet<&str> {
        self.filter.scoop.iter().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = InjectorConfig::default();
        assert!(cfg.filter.enabled);
        assert!(cfg.filter.block_android_package);
        assert!(cfg.is_target("com.google.android.gms"));
        assert!(!cfg.is_target("android"));
        assert!(!cfg.is_target("com.random.app"));
    }

    #[test]
    fn test_filter_disabled() {
        let mut cfg = InjectorConfig::default();
        cfg.filter.enabled = false;
        assert!(cfg.is_target("com.anything"));
    }

    #[test]
    fn test_deny_list() {
        let mut cfg = InjectorConfig::default();
        cfg.filter.deny_packages.push("com.google.android.gms".into());
        assert!(!cfg.is_target("com.google.android.gms"));
    }
}

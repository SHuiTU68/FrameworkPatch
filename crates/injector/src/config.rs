//! injector.toml 配置解析
//!
//! **全局 hook 模型**：FKTee-rs 注入到 keystore2 后，所有走 keystore2 的
//! attestation 请求一律用本模块的 keybox 签发伪造证书链——不再按应用白名单
//! 过滤。本配置仅保留一个全局总开关 `[hook].enabled` 与各事务拦截开关。

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

/// 全局 hook 开关。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// 全局总开关。
    /// - `true`：所有应用的 keystore2 attestation 都用 keybox 伪造。
    /// - `false`：hook 不生效，全部放行（透传原始事务）。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
        }
    }
}

/// 各事务拦截开关（默认全开）。
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
            "配置加载完成: hook.enabled={} (全局模式，所有应用生效)",
            config.hook.enabled
        );
        Ok(config)
    }

    /// hook 是否生效。
    ///
    /// 全局模型下没有“目标应用”概念——要么对所有应用生效，要么完全不拦截。
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
    }

    #[test]
    fn test_disabled() {
        let mut cfg = InjectorConfig::default();
        cfg.hook.enabled = false;
        assert!(!cfg.is_active());
    }

    #[test]
    fn test_parse_global() {
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
    }
}

//! `keybox.xml` 管理器。
//!
//! 包装 [`certgen`] crate 的 keybox 解析功能，将一个 keybox.xml 拆分为
//! EC 与 RSA 两条 [`KeyboxData`]，供 daemon / certgen 在伪造证书链时选用。
//!
//! 解析复用 `certgen::Keybox::from_xml`；按算法（`KeyAlgorithm::Ecdsa` /
//! `KeyAlgorithm::Rsa`）选取后克隆保存，支持热重载。

use anyhow::Result;
use certgen::{KeyAlgorithm, Keybox, KeyboxData};
use std::path::Path;

/// keybox 管理器：持有 EC / RSA 两套证明密钥（可选）。
pub struct KeyboxManager {
    ec: Option<KeyboxData>,
    rsa: Option<KeyboxData>,
}

impl KeyboxManager {
    /// 从 `keybox.xml` 加载。
    ///
    /// - 文件不存在：返回 `None`（调用方走 fallback 模式）。
    /// - 文件存在但解析失败：同样返回 `None` 走 fallback，**不向上抛错**——
    ///   否则 daemon watchdog 会无限重启（崩溃循环）。与 `DaemonConfig::load` 的
    ///   “备份+回退默认”策略保持一致。
    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            log::warn!("keybox 文件不存在: {}", path.display());
            return Ok(None);
        }

        let xml = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("读取 keybox 失败 ({}): {e}", path.display()))?;
        match Keybox::from_xml(&xml) {
            Ok(keybox) => {
                let ec = keybox.select(KeyAlgorithm::Ecdsa).cloned();
                let rsa = keybox.select(KeyAlgorithm::Rsa).cloned();
                log::info!(
                    "keybox 加载完成: EC={}, RSA={}",
                    ec.is_some(),
                    rsa.is_some()
                );
                Ok(Some(Self { ec, rsa }))
            }
            Err(e) => {
                // 解析失败：备份原文件后走 fallback，避免 daemon 崩溃循环
                log::error!("keybox 解析失败，走 fallback 模式: {e}");
                let mut backup = path.as_os_str().to_owned();
                backup.push(".bad");
                let _ = std::fs::write(&backup, &xml);
                log::warn!("已把损坏的 keybox 备份到 {}.bad", path.display());
                Ok(None)
            }
        }
    }

    pub fn has_ec(&self) -> bool {
        self.ec.is_some()
    }

    pub fn has_rsa(&self) -> bool {
        self.rsa.is_some()
    }

    pub fn ec(&self) -> Option<&KeyboxData> {
        self.ec.as_ref()
    }

    pub fn rsa(&self) -> Option<&KeyboxData> {
        self.rsa.as_ref()
    }

    /// 热重载：重新读取 `keybox.xml` 并替换内部 EC / RSA。
    ///
    /// 文件不存在或解析失败时清空已有 keybox（走 fallback），不向上抛错。
    pub fn reload(&mut self, path: &Path) -> Result<()> {
        if !path.exists() {
            log::warn!("热重载时 keybox 文件不存在，清空: {}", path.display());
            self.ec = None;
            self.rsa = None;
            return Ok(());
        }

        let xml = std::fs::read_to_string(path)?;
        match Keybox::from_xml(&xml) {
            Ok(keybox) => {
                self.ec = keybox.select(KeyAlgorithm::Ecdsa).cloned();
                self.rsa = keybox.select(KeyAlgorithm::Rsa).cloned();
                log::info!(
                    "keybox 热重载完成: EC={}, RSA={}",
                    self.has_ec(),
                    self.has_rsa()
                );
                Ok(())
            }
            Err(e) => {
                log::error!("keybox 热重载解析失败，清空走 fallback: {e}");
                self.ec = None;
                self.rsa = None;
                Ok(())
            }
        }
    }
}

//! RPC 服务器框架。
//!
//! 与注入到 keystore2 进程内的 payload 通信。完整的 binder RPC 实现需要
//! rsbinder 或直接 binder ioctl，这里先写框架。
//!
//! 设计意图（后续实现）——**白名单模式**：
//! 1. 创建 binder service（`IOhMyKsService` 或类似）。
//! 2. 等待 payload 连接。
//! 3. 处理来自 keystore2 的拦截事务。
//! 4. 对每个事务：
//!    - 全局开关关 → 透传。
//!    - 调用方 uid 不在白名单中（解析 `/data/system/packages.list` 得到该 uid 的
//!      包名，不在 `allow_packages` 中）→ 透传原始 attestation。
//!    - 否则用 [`certgen`] 伪造证书链。
//!
//! 这样做的理由：keystore2 是系统级单一服务，所有 App 的 attestation 请求
//! 都汇聚到这里。在 keystore2 内部进行白名单过滤，仅对指定应用伪造证书，
//! 其余应用保持真实硬件证书。

use crate::config::{DaemonConfig, InjectorConfig};
use crate::keybox::KeyboxManager;
use anyhow::{bail, Result};
use certgen::CertGen;
use std::collections::HashSet;
use std::path::Path;

/// RPC 服务器：持有配置、keybox 与证书生成器，循环处理 payload 事务。
#[allow(dead_code)]
pub struct RpcServer {
    config: DaemonConfig,
    injector_config: InjectorConfig,
    keybox: Option<KeyboxManager>,
    certgen: CertGen,
}

impl RpcServer {
    pub fn new(
        config: DaemonConfig,
        injector_config: InjectorConfig,
        keybox: Option<KeyboxManager>,
        certgen: CertGen,
    ) -> Self {
        Self {
            config,
            injector_config,
            keybox,
            certgen,
        }
    }

    /// 启动 RPC 服务器。
    ///
    /// 当前为框架模式：仅占位循环。完整的 binder RPC 实现见模块级文档 TODO。
    pub fn run(&mut self) -> Result<()> {
        log::info!("RPC 服务器启动（框架模式）");
        log::info!("注意：binder RPC 实现尚未完成，当前为框架模式");
        if self.injector_config.is_active() {
            log::info!(
                "白名单模式已启用：仅对 {} 个指定应用进行 attestation 伪造",
                self.injector_config.hook.allow_packages.len()
            );
            if self.injector_config.hook.allow_packages.is_empty() {
                log::warn!("白名单为空：当前没有应用被伪造，请添加包名到 allow.list");
            } else {
                for pkg in &self.injector_config.hook.allow_packages {
                    log::info!("  → 伪造: {pkg}");
                }
            }
        } else {
            log::warn!("hook 已禁用：所有事务透传，不伪造任何证书");
        }
        if let Some(kb) = &self.keybox {
            log::info!("keybox: EC={}, RSA={}", kb.has_ec(), kb.has_rsa());
        } else {
            log::warn!("keybox 未加载，将使用 fallback 模式");
        }
        let _ = &self.config;

        // TODO: 完整的 binder RPC 实现
        // 1. 创建 binder service（IOhMyKsService 或类似）
        // 2. 等待 payload 连接
        // 3. 处理来自 keystore2 的拦截事务：
        //    a. 若 !injector_config.is_active() → 透传
        //    b. 若 !uid_allowed(uid) → 透传（不在白名单中）
        //    c. 否则用 certgen 伪造证书链

        // 保持运行
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// 处理 keystore2 事务。
    ///
    /// 白名单模式：
    /// - 全局开关关 → 透传。
    /// - 调用方 uid 不在白名单 → 透传。
    /// - 否则按 code 分发伪造。
    #[allow(dead_code)]
    fn handle_transaction(&self, code: u32, uid: u32, data: &[u8]) -> Result<Vec<u8>> {
        // 全局开关关闭 → 透传（实际由 payload 直接放行，不进入此处）
        if !self.injector_config.is_active() {
            return Ok(data.to_vec());
        }
        // 白名单检查：uid 不在白名单中则透传
        if !self.uid_allowed(uid) {
            log::debug!("uid {uid} 不在白名单中，透传事务 code={code}");
            return Ok(data.to_vec());
        }
        // 根据 code 分发到具体处理函数
        let _ = (code, uid, data);
        // RPC 框架尚未接通，事务处理逻辑未实现——返回 bail 而非 todo!()，
        // 避免在 panic=abort 的 release 构建里直接 abort 整个 daemon。
        bail!("事务处理逻辑尚未实现（RPC 框架占位）")
    }

    /// 判断调用方 uid 是否在白名单中。
    ///
    /// 解析 `/data/system/packages.list`（格式：`pkg uid ...`），收集该 uid 的
    /// 所有包名，与 `allow_packages` 求交集。任一匹配即允许伪造。
    /// 文件不可读 / 解析失败时保守返回 `false`（不伪造，继续透传）——
    /// 因为白名单是"授权列表"，解析失败不应导致全盘伪造。
    #[allow(dead_code)]
    fn uid_allowed(&self, uid: u32) -> bool {
        if self.injector_config.hook.allow_packages.is_empty() {
            return false;
        }
        let allow: HashSet<&str> = self
            .injector_config
            .hook
            .allow_packages
            .iter()
            .map(String::as_str)
            .collect();
        packages_for_uid(Path::new("/data/system/packages.list"), uid)
            .iter()
            .any(|pkg| allow.contains(pkg.as_str()))
    }

    /// 处理 `generateKey` 事务：用 certgen 生成密钥对 + 伪造证书链。
    #[allow(dead_code)]
    fn handle_generate_key(&self, params: &[u8]) -> Result<Vec<u8>> {
        let _ = params;
        bail!("handle_generate_key 尚未实现（RPC 框架占位）")
    }

    /// 处理 `getKeyEntry` 事务：替换证书链。
    #[allow(dead_code)]
    fn handle_get_key_entry(&self, params: &[u8]) -> Result<Vec<u8>> {
        let _ = params;
        bail!("handle_get_key_entry 尚未实现（RPC 框架占位）")
    }
}

/// 从 `/data/system/packages.list` 解析指定 uid 对应的包名列表。
///
/// packages.list 每行格式：`<packageName> <uid> <debugFlag> <dataPath> <seinfo> ...`
/// 只取前两列做 uid 匹配。
fn packages_for_uid(path: &Path, uid: u32) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let pkg = it.next()?;
            let uid_str = it.next()?;
            let pkg_uid: u32 = uid_str.parse().ok()?;
            (pkg_uid == uid).then(|| pkg.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packages_for_uid_parses() {
        let tmp = std::env::temp_dir().join("fktee_packages_list_test");
        std::fs::write(
            &tmp,
            "com.example.app 10042 0 /data/user/0/com.example.app default\n\
             com.other 10043 0 /data/user/0/com.other default\n",
        )
        .unwrap();
        let pkgs = packages_for_uid(&tmp, 10042);
        assert_eq!(pkgs, vec!["com.example.app".to_string()]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_packages_for_uid_missing_file() {
        let pkgs = packages_for_uid(Path::new("/nonexistent/packages.list"), 10042);
        assert!(pkgs.is_empty());
    }
}
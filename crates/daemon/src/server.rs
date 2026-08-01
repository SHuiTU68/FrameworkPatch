//! RPC 服务器框架。
//!
//! 与注入到 keystore2 进程内的 payload 通信。完整的 binder RPC 实现需要
//! rsbinder 或直接 binder ioctl，这里先写框架。
//!
//! 设计意图（后续实现）：
//! 1. 创建 binder service（`IOhMyKsService` 或类似）。
//! 2. 等待 payload 连接。
//! 3. 处理来自 keystore2 的拦截事务。
//! 4. 对每个事务：
//!    a. 检查 `callingUid` → 解析包名 → 检查是否在 scoop。
//!    b. 若在 scoop，用 [`certgen`] 伪造证书链。
//!    c. 返回伪造结果。

use crate::config::{DaemonConfig, InjectorConfig};
use crate::keybox::KeyboxManager;
use anyhow::Result;
use certgen::CertGen;

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
        log::info!(
            "scoop: {} 个包",
            self.injector_config.filter.scoop.len()
        );
        if let Some(kb) = &self.keybox {
            log::info!("keybox: EC={}, RSA={}", kb.has_ec(), kb.has_rsa());
        } else {
            log::warn!("keybox 未加载，将使用 fallback 模式");
        }

        // TODO: 完整的 binder RPC 实现
        // 1. 创建 binder service（IOhMyKsService 或类似）
        // 2. 等待 payload 连接
        // 3. 处理来自 keystore2 的拦截事务
        // 4. 对每个事务：
        //    a. 检查 callingUid → 解析包名 → 检查是否在 scoop
        //    b. 如果在 scoop，用 certgen 伪造证书链
        //    c. 返回伪造结果

        // 保持运行
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// 处理 keystore2 事务。
    ///
    /// 1. 从 uid 解析包名。
    /// 2. 检查是否在 scoop。
    /// 3. 根据 `code` 分发到具体处理函数。
    #[allow(dead_code)]
    fn handle_transaction(&self, code: u32, uid: u32, data: &[u8]) -> Result<Vec<u8>> {
        // 1. 从 uid 解析包名
        // 2. 检查是否在 scoop
        // 3. 根据 code 分发到具体处理函数
        let _ = (code, uid, data);
        todo!("事务处理逻辑")
    }

    /// 处理 `generateKey` 事务：用 certgen 生成密钥对 + 伪造证书链。
    #[allow(dead_code)]
    fn handle_generate_key(&self, uid: u32, params: &[u8]) -> Result<Vec<u8>> {
        let _ = (uid, params);
        todo!()
    }

    /// 处理 `getKeyEntry` 事务：替换证书链。
    #[allow(dead_code)]
    fn handle_get_key_entry(&self, uid: u32, params: &[u8]) -> Result<Vec<u8>> {
        let _ = (uid, params);
        todo!()
    }

    /// 检查 uid 是否在 target 中。
    #[allow(dead_code)]
    fn is_target_uid(&self, uid: u32) -> bool {
        // 从 uid 解析包名
        let packages = self.get_packages_for_uid(uid);
        packages
            .iter()
            .any(|pkg| self.injector_config.is_target(pkg))
    }

    /// 从 uid 获取包名列表。
    ///
    /// TODO: 通过 PM `pm packages for uid` 或读 `/data/system/packages.list`。
    #[allow(dead_code)]
    fn get_packages_for_uid(&self, _uid: u32) -> Vec<String> {
        Vec::new()
    }
}

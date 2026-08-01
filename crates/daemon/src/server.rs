//! RPC 服务器框架。
//!
//! 与注入到 keystore2 进程内的 payload 通信。完整的 binder RPC 实现需要
//! rsbinder 或直接 binder ioctl，这里先写框架。
//!
//! 设计意图（后续实现）——**全局 hook 模型**：
//! 1. 创建 binder service（`IOhMyKsService` 或类似）。
//! 2. 等待 payload 连接。
//! 3. 处理来自 keystore2 的拦截事务。
//! 4. 对每个事务：只要 `[hook].enabled` 为真，一律用 [`certgen`] 伪造证书链，
//!    **不再按调用方 uid / 包名过滤**——所有走 keystore2 的应用都会拿到
//!    由本模块 keybox 签发的伪造 attestation 证书链。
//!
//! 这样做的理由：keystore2 是系统级单一服务，所有 App 的 attestation 请求
//! 都汇聚到这里。在 keystore2 内部全局 hook，比逐 App 注入更彻底、更稳定，
//! 也不会漏掉任何调用方。

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
        if self.injector_config.is_active() {
            log::info!("hook 已启用：全局模式，所有应用的 attestation 都将被伪造");
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
        //    a. 若 injector_config.is_active() 为真（全局开关），用 certgen 伪造证书链
        //    b. 否则透传原始事务
        //    注意：不再按 callingUid / 包名过滤——所有调用方一视同仁。

        // 保持运行
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// 处理 keystore2 事务。
    ///
    /// 全局模型：只要 hook 启用，对所有调用方一律伪造；否则透传。
    /// 不再根据 uid 解析包名做白名单判断。
    #[allow(dead_code)]
    fn handle_transaction(&self, code: u32, uid: u32, data: &[u8]) -> Result<Vec<u8>> {
        // 全局开关关闭 → 透传（实际由 payload 直接放行，不进入此处）
        if !self.injector_config.is_active() {
            return Ok(data.to_vec());
        }
        // 根据 code 分发到具体处理函数
        let _ = (code, uid, data);
        todo!("事务处理逻辑")
    }

    /// 处理 `generateKey` 事务：用 certgen 生成密钥对 + 伪造证书链。
    #[allow(dead_code)]
    fn handle_generate_key(&self, params: &[u8]) -> Result<Vec<u8>> {
        let _ = params;
        todo!()
    }

    /// 处理 `getKeyEntry` 事务：替换证书链。
    #[allow(dead_code)]
    fn handle_get_key_entry(&self, params: &[u8]) -> Result<Vec<u8>> {
        let _ = params;
        todo!()
    }
}

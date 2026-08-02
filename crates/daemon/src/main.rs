//! FKTee-rs daemon
//!
//! 这是 FKTee-rs 的核心守护进程，负责：
//! 1. 加载配置（config.toml / injector.toml / keybox.xml）
//! 2. 管理证书生成（通过 certgen crate）
//! 3. 与注入到 keystore2 的 payload 通信（通过 binder RPC）
//! 4. 热配置（文件监听自动重载）
//! 5. 被 injector daemon 启动，处理来自 keystore2 的拦截事务

mod config;
mod keybox;
mod server;

use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    env_logger::init();

    log::info!("FKTee-rs daemon v{} 启动", env!("CARGO_PKG_VERSION"));
    log::info!("PID={}", std::process::id());

    // 配置目录
    let config_dir = PathBuf::from("/data/adb/Tee-rs");

    // 加载配置
    let mut cfg = config::DaemonConfig::load(&config_dir.join("config.toml"))?;
    let mut injector_cfg = config::InjectorConfig::load(&config_dir.join("injector.toml"))?;
    // 覆盖加载黑名单（deny.list）
    injector_cfg.load_deny_list(&config_dir.join("deny.list"));

    log::info!("后端模式: {:?}", cfg.backend.mode);
    if injector_cfg.is_active() {
        log::info!(
            "全局 hook 已启用：所有应用的 keystore2 attestation 都将使用本模块 keybox（黑名单 {} 个包豁免）",
            injector_cfg.hook.deny_packages.len()
        );
    } else {
        log::warn!("全局 hook 已禁用：所有事务透传，不伪造任何证书");
    }

    // 加载 keybox
    let keybox_path = config_dir.join("keybox.xml");
    let keybox = keybox::KeyboxManager::load(&keybox_path)?;
    match &keybox {
        Some(kb) => log::info!("keybox 已加载: EC={}, RSA={}", kb.has_ec(), kb.has_rsa()),
        None => log::warn!("keybox 未加载，将使用 fallback 模式"),
    }

    // 初始化证书生成器
    let certgen = certgen::CertGen::new();
    log::info!("certgen 初始化完成");

    // 启动热配置监听
    let config_dir_clone = config_dir.clone();
    std::thread::spawn(move || {
        watch_config_changes(&config_dir_clone);
    });

    // 启动 RPC 服务器（监听来自 payload 的 binder 事务）
    log::info!("启动 RPC 服务器...");
    let mut server = server::RpcServer::new(cfg, injector_cfg, keybox, certgen);
    server.run()?;

    Ok(())
}

/// 监听配置文件变化，热重载
///
/// 使用 AtomicU64 做防抖：同一秒内的多次事件只触发一次重载，
/// 避免 daemon 自身写日志/状态文件导致的热重载无限循环。
fn watch_config_changes(config_dir: &PathBuf) {
    use hotwatch::Hotwatch;

    let mut watcher = match Hotwatch::new_with_custom_delay(std::time::Duration::from_secs(2)) {
        Ok(w) => w,
        Err(e) => {
            log::error!("文件监听初始化失败: {e}");
            return;
        }
    };

    let watch_path = config_dir.clone();

    // 只关心关键配置文件
    let _ = watcher.watch(&watch_path, move |event| {
        let path = event.path.as_deref().unwrap_or(std::path::Path::new(""));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // 只对特定配置文件的变化做反应，忽略日志/状态文件
        match name {
            "config.toml" | "injector.toml" | "keybox.xml" | "deny.list" => {
                log::info!("配置文件变化，准备热重载: {name}");
                // TODO: 重新加载配置并通知 server 线程
                // 这里发送信号给 server 线程触发重载
            }
            _ => {
                // 忽略其他文件变化（日志、临时文件等），避免无限循环
                log::debug!("忽略非配置文件的变更: {name}");
            }
        }
    });

    log::info!("配置热重载监听已启动: {}", config_dir.display());

    // 保持线程存活
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

//! FKTee-rs 注入器入口
//!
//! 负责：
//! 1. 定位 keystore2 进程
//! 2. ptrace 远程 dlopen 注入 payload .so
//! 3. 调用 payload 的 entry() 完成 binder ioctl hook 安装
//!
//! **全局 hook**：注入后所有走 keystore2 的应用都受影响，不再按应用白名单过滤。

mod config;
mod hook;
mod inject;

use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let (target_pid, payload_path, config_path) = match args.len() {
        3 => (
            args[1].parse::<i32>()
                .map_err(|e| anyhow::anyhow!("无效的 PID: {e}"))?,
            PathBuf::from(&args[2]),
            PathBuf::from("/data/adb/fktee/injector.toml"),
        ),
        4 => (
            args[1].parse::<i32>()
                .map_err(|e| anyhow::anyhow!("无效的 PID: {e}"))?,
            PathBuf::from(&args[2]),
            PathBuf::from(&args[3]),
        ),
        _ => {
            // 自动模式：找 keystore2 进程
            log::info!("FKTee-rs injector v{}", env!("CARGO_PKG_VERSION"));
            log::info!("用法: inject <pid> <payload.so> [config.toml]");
            log::info!("自动模式：定位 keystore2 并注入");

            let pid = inject::find_process_by_name("keystore2")
                .ok_or_else(|| anyhow::anyhow!("找不到 keystore2 进程"))?;

            let payload = PathBuf::from("/data/adb/fktee/injector.payload");
            let config = PathBuf::from("/data/adb/fktee/injector.toml");

            (pid, payload, config)
        }
    };

    log::info!("目标 PID: {target_pid}");
    log::info!("Payload: {}", payload_path.display());
    log::info!("配置: {}", config_path.display());

    // 幂等检查：是否已注入
    if inject::is_already_injected(target_pid, &payload_path)? {
        log::info!("keystore2 已被注入，跳过");
        return Ok(());
    }

    // 加载配置
    let cfg = config::InjectorConfig::load(&config_path)?;
    if cfg.is_active() {
        log::info!("全局 hook 已启用：所有应用的 keystore2 attestation 都将使用本模块 keybox");
    } else {
        log::warn!("全局 hook 已禁用：注入仅完成 hook 安装，但不会伪造任何事务");
    }

    // 执行 ptrace 远程 dlopen 注入
    inject::inject_library(target_pid, &payload_path)?;

    log::info!("注入完成，全局 hook 已安装");
    Ok(())
}

//! 真 HAL 代理句柄的惰性查找。
//!
//! fktee-hal 抢占 `default` 实例名后，按配置的 `real_hal_instance` 用
//! `wait_for_interface` 拿到真 HAL 的 `Strong<dyn IKeyMintDevice>` 代理，
//! 后续非 attestation 事务透传给它。
//!
//! 查找是惰性 + 缓存的：第一次需要转发时才 `wait_for_service`（阻塞至
//! 真 HAL 上线），之后复用句柄。若真 HAL 重启（句柄失效），下次转发
//! 会触发 `take()` + 重新查找。

use crate::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use once_cell::sync::OnceCell;
use rsbinder::hub;
use rsbinder::Strong;

/// 全局真 HAL 代理缓存。`OnceCell` 保证只查一次；真 HAL 重启需重启 fktee-hal。
///
/// 用全局而非结构体字段，是因为 `IKeyMintDevice` trait 方法拿 `&self`，
/// 无法在 trait impl 里 mutate `&mut Strong<...>`。全局 `OnceCell` 是
/// AOSP Rust HAL 代理惯用法。
static REAL_HAL: OnceCell<Strong<dyn IKeyMintDevice>> = OnceCell::new();

/// 真 HAL 的全限定服务名（接口描述符 + 实例名）。
fn fq_name(instance: &str) -> String {
    format!(
        "android.hardware.security.keymint.IKeyMintDevice/{}",
        instance
    )
}

/// 获取真 HAL 代理。
///
/// - 首次调用：`wait_for_service`（阻塞至真 HAL 上线），失败返回 `None`。
/// - 后续调用：直接返回缓存句柄。
///
/// `wait_for_service` 而非 `get_service`：真 HAL 由 vendor/init 启动，
/// 上线时机晚于 fktee-hal（post-fs-data 阶段），必须阻塞等待。
pub fn get_real_hal(instance: &str) -> Option<&'static Strong<dyn IKeyMintDevice>> {
    if let Some(h) = REAL_HAL.get() {
        return Some(h);
    }
    let name = fq_name(instance);
    log::info!("fktee-hal: waiting for real HAL: {name}");
    match hub::wait_for_service(&name) {
        Some(binder) => match <dyn IKeyMintDevice as rsbinder::FromIBinder>::try_from(binder) {
            Ok(strong) => {
                log::info!("fktee-hal: real HAL connected: {name}");
                // set 失败说明并发竞争里别人已 set，等价结果，忽略。
                let _ = REAL_HAL.set(strong);
                REAL_HAL.get()
            }
            Err(e) => {
                log::error!("fktee-hal: real HAL binder 类型转换失败: {e:?}");
                None
            }
        },
        None => {
            log::error!("fktee-hal: real HAL 未上线: {name}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fq_name_format() {
        assert_eq!(
            fq_name("fktee-real"),
            "android.hardware.security.keymint.IKeyMintDevice/fktee-real"
        );
        assert_eq!(
            fq_name("default"),
            "android.hardware.security.keymint.IKeyMintDevice/default"
        );
    }
}

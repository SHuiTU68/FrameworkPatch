//! binder ioctl hook
//!
//! 参考 OhMyKeymint / ForgeStore / TEESimulator-RS 的 hook 实现。
//! 使用 LSPlt（C++ PLT hook 库）对 libbinder.so 的 ioctl 做 PLT hook，
//! 拦截 BINDER_WRITE_READ 中的 BR_TRANSACTION 事务，**全局**改写 / 转发给
//! daemon 处理。
//!
//! **全局 hook 模型**：不再按调用方 uid / 包名做白名单过滤。因为 hook 点在
//! keystore2 进程内部，所有 App 的 attestation 请求都汇聚于此，统一改写即可
//! 让所有应用拿到由本模块 keybox 签发的伪造证书链。是否生效仅由
//! `[hook].enabled` 全局开关决定（见 payload 读取的 injector.toml）。
//!
//! LSPlt 是 C++ 库，通过 FFI 调用。
//! 后续需要 vendor LSPlt 源码到 vendor/lsplt/ 并通过 build.rs 编译链接。
//! 当前阶段：FFI 声明已就绪，hook 注册逻辑标注 TODO（需 LSPlt 编译集成）。

// 本模块为 binder ioctl hook 的设计骨架。LSPlt 尚未 vendor，相关 FFI /
// binder 结构体 / ioctl 常量当前均为占位声明，待 build.rs 集成 LSPlt 后启用。
#![allow(dead_code)]

use anyhow::Result;

/// 后门 code（daemon 握手用）
const BACKDOOR_CODE: u32 = 0xfeedface;

/// binder ioctl 命令
///
/// `BINDER_WRITE_READ = _IOWR('b', 1, struct binder_write_read)`
/// `_IOWR = _IOC_READ|_IOC_WRITE = (2|1)<<30 = 3<<30`（Linux asm-generic/ioctl.h:
/// `_IOC_READ=2`, `_IOC_WRITE=1`）。
const BINDER_WRITE_READ: u32 = _iowr(b'b', 1, std::mem::size_of::<BinderWriteRead>() as u32);

/// binder 返回命令
///
/// `BR_TRANSACTION        = _IOR('r', 2,  struct binder_transaction_data)`
/// `BR_TRANSACTION_SEC_CTX = _IOR('r', 42, struct binder_transaction_data_secctx)`
/// （见内核 `include/uapi/linux/android/binder.h`；不同内核版本 nr 偶有差异，
///  启用真实 hook 前请对照目标内核 binder.h 校验。）
const BR_TRANSACTION: u32 = _ior(b'r', 2, std::mem::size_of::<BinderTransactionData>() as u32);
const BR_TRANSACTION_SEC_CTX: u32 =
    _ior(b'r', 42, std::mem::size_of::<BinderTransactionDataSecCtx>() as u32);

// ============================================================================
// LSPlt FFI 声明
// LSPlt 是 C++ 库（https://github.com/LSPosed/LSPlt），
// 后续通过 build.rs vendor 编译。当前为声明，调用处标注 TODO。
//
// 注意：暂不添加 `#[link(name = "lsplt", ...)]`——liblsplt.a 尚未 vendor，
// 加上会导致链接器报 `unable to find library -llsplt`（CI 构建失败）。
// 待 build.rs 集成 LSPlt 后再启用 link 属性。
// ============================================================================

#[allow(non_camel_case_types)]
#[allow(dead_code)] // LSPlt 尚未 vendor，FFI 符号当前未调用，待集成后启用
mod lsplt_ffi {
    use std::os::raw::{c_char, c_int, c_void};

    /// LSPlt hook handler 函数指针类型
    pub type HookHandler =
        extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;

    /// 注册 PLT hook
    /// 返回 0 成功，非 0 失败
    //
    // 故意不加 `#[link]`：符号当前未调用，加 link 属性会强制链接器寻找
    // 不存在的 liblsplt.a。后续 vendor LSPlt 并在 build.rs 中链接后，
    // 再恢复 `#[link(name = "lsplt", kind = "static")]`。
    extern "C" {
        pub fn lsplt_register_hook(
            lib_name: *const c_char,
            symbol: *const c_char,
            replacement: *const c_void,
            original: *mut *mut c_void,
        ) -> c_int;

        /// 提交所有已注册的 hook
        pub fn lsplt_commit_hooks() -> c_int;

        /// 取消所有 hook
        pub fn lsplt_unhook_all() -> c_int;
    }
}

/// 初始化 hook
///
/// 这个函数在 payload 被 dlopen 进 keystore2 后由 entry() 调用。
/// 它用 LSPlt 注册对 libbinder.so 的 ioctl PLT hook。
pub fn init_hook() -> Result<()> {
    log::info!("初始化 binder ioctl hook");

    // TODO: vendor LSPlt C++ 源码后启用
    // 当前 LSPlt 尚未 vendor，hook 注册为占位实现
    //
    // 完整实现流程：
    // 1. vendor LSPlt 源码到 vendor/lsplt/
    // 2. 创建 build.rs 编译 LSPlt 静态库
    // 3. 注册 hook：
    //    let libbinder = b"libbinder.so\0";
    //    let ioctl_sym = b"ioctl\0";
    //    let mut original_ioctl: *mut c_void = std::ptr::null_mut();
    //    unsafe {
    //        lsplt_ffi::lsplt_register_hook(
    //            libbinder.as_ptr() as *const c_char,
    //            ioctl_sym.as_ptr() as *const c_char,
    //            hooked_ioctl as *const c_void,
    //            &mut original_ioctl,
    //        );
    //        lsplt_ffi::lsplt_commit_hooks();
    //    }
    //    ORIGINAL_IOCTL.store(original_ioctl, Ordering::SeqCst);

    log::warn!("LSPlt 尚未 vendor，binder ioctl hook 注册为占位实现");
    log::warn!("当前 hook 不会实际拦截 binder 事务");
    log::warn!("后续需要：1) vendor LSPlt C++ 源码 2) 创建 build.rs 3) 启用上面的注册代码");

    Ok(())
}

/// 被注入的 ioctl hook 函数
///
/// 拦截 binder 事务（全局，不按调用方过滤）：
/// 1. 先调用原始 ioctl
/// 2. 检查返回的 BR_TRANSACTION / BR_TRANSACTION_SEC_CTX
/// 3. 解析 binder_transaction_data 获取 target.ptr / cookie / code
/// 4. 全局处理（见 `[hook].enabled`）：
///    - BACKDOOR_CODE + uid==0 → 返回 g_interceptor binder（daemon 握手）
///    - uid==0 普通事务 → 把 sender_euid 从 0 改成 1000
///    - attestation 相关事务 → 改写 target.ptr/cookie 到 g_stub，由 daemon
///      用 keybox 签发伪造证书链。所有调用方一视同仁，不做白名单判断。
#[no_mangle]
pub extern "C" fn hooked_ioctl(_fd: i32, _request: u32, _arg: *mut std::ffi::c_void) -> i32 {
    // 先调用原始 ioctl
    // let original = ORIGINAL_IOCTL.load(Ordering::SeqCst);
    // if original.is_null() { return -1; }
    // let result = (original as extern "C" fn(i32, u32, *mut c_void) -> i32)(fd, request, arg);

    // if request != BINDER_WRITE_READ {
    //     return result;
    // }

    // 解析 binder_write_read 结构
    // let bwr = &mut *(arg as *mut BinderWriteRead);
    // if bwr.read_consumed == 0 {
    //     return result;
    // }

    // 遍历 read buffer 中的命令
    // let read_buf = bwr.read_buffer as *mut u32;
    // let mut consumed = 0;
    // while consumed < bwr.read_consumed {
    //     let cmd = *read_buf.add(consumed / 4);
    //     match cmd {
    //         BR_TRANSACTION | BR_TRANSACTION_SEC_CTX => {
    //             // 解析 binder_transaction_data
    //             // 获取 target.ptr, cookie, code, sender_euid
    //             // 按 target 过滤规则处理
    //         }
    //         _ => {}
    //     }
    //     consumed += ...;
    // }

    // TODO: 完整实现（需 LSPlt vendor 后）
    0
}

// ============================================================================
// binder 结构体定义（与内核一致）
// 当前为占位声明（hook 未实际启用），待 LSPlt vendor 后启用。
// ============================================================================

#[allow(dead_code)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BinderWriteRead {
    write_size: i64,
    write_consumed: i64,
    write_buffer: u64,
    read_size: i64,
    read_consumed: i64,
    read_buffer: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BinderTransactionData {
    target: BinderPtrCookie,
    cookie: u64,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: i32,
    data_size: u64,
    offsets_size: u64,
    data_ptr: BinderPtr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BinderPtrCookie {
    ptr: u64,
    cookie: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BinderPtr {
    buffer: u64,
    offsets: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BinderTransactionDataSecCtx {
    transaction_data: BinderTransactionData,
    sec_ctx: u64,
}

// ============================================================================
// ioctl 宏（与内核 _IOW/_IOR/_IOWR 一致；Linux asm-generic/ioctl.h）
//
// _IOC_NRBITS=8, _IOC_TYPEBITS=8, _IOC_SIZEBITS=14, _IOC_DIRBITS=2
// _IOC(dir, type, nr, size) = (dir<<30) | (size<<16) | (type<<8) | nr
// _IOC_NONE=0, _IOC_WRITE=1, _IOC_READ=2
//   _IOR  = _IOC_READ       = 2<<30
//   _IOW  = _IOC_WRITE      = 1<<30
//   _IOWR = _IOC_READ|WRITE = 3<<30
// ============================================================================

/// `_IOWR(type, nr, size)`：dir = READ|WRITE = 3。
const fn _iowr(typ: u8, nr: u32, size: u32) -> u32 {
    (3 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

/// `_IOR(type, nr, size)`：dir = READ = 2。binder 返回命令（BR_*）用此编码。
const fn _ior(typ: u8, nr: u32, size: u32) -> u32 {
    (2 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_consts() {
        // 确保常量在编译期正确计算且非零
        assert_ne!(BINDER_WRITE_READ, 0);
        assert_ne!(BR_TRANSACTION, 0);
        assert_ne!(BR_TRANSACTION_SEC_CTX, 0);
        // 方向位校验：BINDER_WRITE_READ 必须是 _IOWR（dir=3）
        assert_eq!(BINDER_WRITE_READ >> 30, 3);
        // BR_* 必须是 _IOR（dir=2）
        assert_eq!(BR_TRANSACTION >> 30, 2);
        assert_eq!(BR_TRANSACTION_SEC_CTX >> 30, 2);
        // nr 校验
        assert_eq!((BR_TRANSACTION >> 0) & 0xff, 2);
        assert_eq!((BR_TRANSACTION_SEC_CTX >> 0) & 0xff, 42);
    }
}

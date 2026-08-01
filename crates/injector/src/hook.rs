//! binder ioctl hook
//!
//! 参考 OhMyKeymint / ForgeStore / TEESimulator-RS 的 hook 实现。
//! 使用 LSPlt（C++ PLT hook 库）对 libbinder.so 的 ioctl 做 PLT hook，
//! 拦截 BINDER_WRITE_READ 中的 BR_TRANSACTION 事务，
//! 按 target 过滤规则改写/转发给 daemon 处理。
//!
//! LSPlt 是 C++ 库，通过 FFI 调用。
//! 后续需要 vendor LSPlt 源码到 vendor/lsplt/ 并通过 build.rs 编译链接。
//! 当前阶段：FFI 声明已就绪，hook 注册逻辑标注 TODO（需 LSPlt 编译集成）。

use anyhow::Result;

/// 后门 code（daemon 握手用）
const BACKDOOR_CODE: u32 = 0xfeedface;

/// binder ioctl 命令
const BINDER_WRITE_READ: u32 = _iowr(b'b', 1, ());

/// binder 返回命令
const BR_TRANSACTION: u32 = _ior_br(b'r', 12, ());
const BR_TRANSACTION_SEC_CTX: u32 = _ior_br(b'r', 15, ());

// ============================================================================
// LSPlt FFI 声明
// LSPlt 是 C++ 库（https://github.com/LSPosed/LSPlt），
// 后续通过 build.rs vendor 编译。当前为声明，调用处标注 TODO。
// ============================================================================

#[allow(non_camel_case_types)]
mod lsplt_ffi {
    use std::os::raw::{c_char, c_int, c_void};

    /// LSPlt hook handler 函数指针类型
    pub type HookHandler =
        extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;

    /// 注册 PLT hook
    /// 返回 0 成功，非 0 失败
    #[link(name = "lsplt", kind = "static")]
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
/// 拦截 binder 事务：
/// 1. 先调用原始 ioctl
/// 2. 检查返回的 BR_TRANSACTION / BR_TRANSACTION_SEC_CTX
/// 3. 解析 binder_transaction_data 获取 target.ptr / cookie / code
/// 4. 按 target 过滤规则处理：
///    - BACKDOOR_CODE + uid==0 → 返回 g_interceptor binder（daemon 握手）
///    - uid==0 普通事务 → 把 sender_euid 从 0 改成 1000
///    - 注册的目标 binder → 改写 target.ptr/cookie 到 g_stub
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
// ============================================================================

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
// ioctl 宏（与内核 _IOW/_IOR 一致）
// ============================================================================

/// _IOWR(type, nr, size) = 2 << 30 | size << 16 | type << 8 | nr
const fn _iowr(typ: u8, nr: u32, _size_marker: ()) -> u32 {
    let size = std::mem::size_of::<BinderWriteRead>() as u32;
    (2 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

/// _IOR(type, nr, size) = 2 << 30 | size << 16 | type << 8 | nr
/// 注意：binder 返回命令使用不同的编码方式
const fn _ior_br(typ: u8, nr: u32, _size_marker: ()) -> u32 {
    let size = std::mem::size_of::<BinderTransactionData>() as u32;
    (2 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_consts() {
        // 确保常量在编译期正确计算
        assert_ne!(BINDER_WRITE_READ, 0);
        assert_ne!(BR_TRANSACTION, 0);
        assert_ne!(BR_TRANSACTION_SEC_CTX, 0);
    }
}

//! FKTee-rs 注入 payload 库
//!
//! 这个 .so 被 ptrace 注入到 keystore2 进程后，
//! entry() 函数会被远程调用。
//! 它负责：
//! 1. 初始化日志
//! 2. 安装 binder ioctl hook（LSPlt）
//! 3. 与 daemon 建立 RPC 通信
//!
//! 注意：作为 cdylib，它需要内联 hook 模块的实现，
//! 不能引用 bin crate 的模块。

use std::ffi::c_void;
use std::os::raw::c_int;

/// payload 入口点
///
/// 被 inject 二进制通过远程 dlsym + 远程调用执行。
/// handle 是 android_dlopen_ext 返回的 .so handle。
#[no_mangle]
pub extern "C" fn entry(_handle: *mut c_void) {
    // 初始化日志（输出到 logcat）
    // 注意：env_logger 在被注入进程中可能无法正常工作（没有 env），
    // OhMyKeymint 用的是 __android_log_print 直接输出
    init_logging();

    log_info("FKTee-rs payload 已加载到 keystore2 进程");

    // 安装 binder ioctl hook
    if let Err(e) = init_hook() {
        log_error(&format!("hook 初始化失败: {e}"));
        return;
    }

    log_info("FKTee-rs hook 安装完成，开始拦截 keystore2 事务");
}

/// 初始化日志（直接用 __android_log_print，不依赖 env_logger）
fn init_logging() {
    // env_logger 在被注入进程中可能没有环境变量，直接用 Android log
}

fn log_info(msg: &str) {
    let c_msg = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(4, b"FKTee\0".as_ptr() as *const _, c_msg.as_ptr());
    }
}

fn log_error(msg: &str) {
    let c_msg = std::ffi::CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(6, b"FKTee\0".as_ptr() as *const _, c_msg.as_ptr());
    }
}

#[link(name = "log")]
extern "C" {
    fn __android_log_print(prio: c_int, tag: *const std::os::raw::c_char, msg: *const std::os::raw::c_char) -> c_int;
}

/// 初始化 binder ioctl hook
///
/// TODO: vendor LSPlt 后实现
/// 当前为占位实现，不实际 hook
fn init_hook() -> anyhow::Result<()> {
    log_info("初始化 binder ioctl hook（占位实现）");
    log_info("TODO: vendor LSPlt 后启用实际 hook");
    Ok(())
}

/// 被注入的 ioctl hook 函数（LSPlt 注册后替换 libbinder.so 的 ioctl）
#[no_mangle]
pub extern "C" fn hooked_ioctl(_fd: c_int, _request: u32, _arg: *mut c_void) -> c_int {
    // TODO: 完整实现 binder 事务拦截
    // 参考 hook.rs 中的设计
    0
}

/// payload 的构造函数（.so 加载时自动执行，但实际初始化在 entry() 中）
#[cfg(target_os = "android")]
#[link_section = ".init_array"]
static INIT_ARRAY: [extern "C" fn(); 1] = [init_array_entry];

#[cfg(target_os = "android")]
extern "C" fn init_array_entry() {
    // 不在此处初始化，等待 entry() 被远程调用
}

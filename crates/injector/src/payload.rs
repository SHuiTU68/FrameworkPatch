//! FKTee-rs 注入 payload 库
//!
//! 这个 .so 被 ptrace 注入到 keystore2 进程后，
//! entry() 函数会被远程调用。
//! 它负责：
//! 1. 初始化日志
//! 2. 读取 injector.toml 的 `[hook].enabled` 全局开关
//! 3. 安装 binder ioctl hook（LSPlt）——**全局拦截**，所有走 keystore2 的
//!    应用 attestation 请求都改写，不做应用白名单过滤
//! 4. 与 daemon 建立 RPC 通信
//!
//! 注意：作为 cdylib，它通过 `#[path]` 内联 hook 模块的实现，
//! 不能引用 bin crate 的模块。

// 复用 hook.rs 的实现（统一一份 hook 代码，避免 bin/lib 各持一份占位 stub）。
#[path = "hook.rs"]
mod hook;

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

    // 安装 binder ioctl hook（全局：所有应用 attestation 都改写）
    if let Err(e) = hook::init_hook() {
        log_error(&format!("hook 初始化失败: {e}"));
        return;
    }

    log_info("FKTee-rs 全局 hook 安装完成，开始拦截所有 keystore2 attestation 事务");
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

// liblog 只在 Android 目标上存在。host 工具链（cargo test / clippy）没有 -llog，
// 因此非 Android 平台提供一个空 stub，使本 crate 在 host 上也能编译/测试。
#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    fn __android_log_print(
        prio: c_int,
        tag: *const std::os::raw::c_char,
        msg: *const std::os::raw::c_char,
    ) -> c_int;
}

#[cfg(not(target_os = "android"))]
unsafe extern "C" fn __android_log_print(
    _prio: c_int,
    _tag: *const std::os::raw::c_char,
    _msg: *const std::os::raw::c_char,
) -> c_int {
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

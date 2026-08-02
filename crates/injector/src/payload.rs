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
use std::sync::atomic::AtomicPtr;

/// 运行时缓存的 __android_log_print 函数指针
/// 用运行时 dlsym 查找，避免编译期链接 liblog.so（keystore2 进程可能没有 liblog）
static ANDROID_LOG_PRINT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// 日志优先级常量
const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;

/// payload 入口点
///
/// 被 inject 二进制通过远程 dlsym + 远程调用执行。
/// handle 是 android_dlopen_ext 返回的 .so handle。
#[no_mangle]
pub extern "C" fn entry(_handle: *mut c_void) {
    // 初始化日志（运行时查找 __android_log_print）
    init_logging();

    log_info("FKTee-rs payload 已加载到 keystore2 进程");

    // 安装 binder ioctl hook（全局：所有应用 attestation 都改写）
    if let Err(e) = hook::init_hook() {
        log_error(&format!("hook 初始化失败: {e}"));
        return;
    }

    log_info("FKTee-rs 全局 hook 安装完成，开始拦截所有 keystore2 attestation 事务");
}

/// 初始化日志：通过运行时 dlsym 查找 __android_log_print
///
/// 不依赖编译期 `#[link(name = "log")]`，避免 payload .so 产生 NEEDED liblog.so
/// 依赖，从而解决 keystore2 进程可能没有 liblog.so 导致 android_dlopen_ext 失败的问题。
fn init_logging() {
    // 只在首次调用时查找一次
    if ANDROID_LOG_PRINT.load(std::sync::atomic::Ordering::Relaxed).is_null() {
        unsafe {
            let handle = libc::dlopen(
                b"liblog.so\0".as_ptr() as *const _,
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
            );
            if !handle.is_null() {
                let func = libc::dlsym(
                    handle,
                    b"__android_log_print\0".as_ptr() as *const _,
                );
                if !func.is_null() {
                    ANDROID_LOG_PRINT.store(func, std::sync::atomic::Ordering::Relaxed);
                }
                libc::dlclose(handle);
            }
        }
    }
}

fn log_info(msg: &str) {
    android_log(ANDROID_LOG_INFO, msg);
}

fn log_error(msg: &str) {
    android_log(ANDROID_LOG_ERROR, msg);
}

/// 内部日志函数：通过运行时函数指针调用 __android_log_print
///
/// 如果运行时未找到 __android_log_print（liblog.so 不存在），
/// 静默忽略日志——比整个 payload 加载失败要好。
fn android_log(prio: c_int, msg: &str) {
    let func_ptr = ANDROID_LOG_PRINT.load(std::sync::atomic::Ordering::Relaxed);
    if func_ptr.is_null() {
        // 回退：尝试用 write syscall 输出到 stderr
        unsafe {
            let _ = libc::write(
                2,
                b"[FKTee] \0".as_ptr() as *const _,
                8,
            );
            let _ = libc::write(2, msg.as_ptr() as *const _, msg.len());
            let _ = libc::write(2, b"\n\0".as_ptr() as *const _, 1);
        }
        return;
    }

    let tag = b"FKTee\0";
    let c_msg = match std::ffi::CString::new(msg) {
        Ok(s) => s,
        Err(_) => return,
    };

    unsafe {
        let log_fn: unsafe extern "C" fn(
            c_int,
            *const std::os::raw::c_char,
            *const std::os::raw::c_char,
        ) -> c_int = std::mem::transmute(func_ptr);
        log_fn(prio, tag.as_ptr() as *const _, c_msg.as_ptr());
    }
}

/// payload 的构造函数（.so 加载时自动执行，但实际初始化在 entry() 中）
#[cfg(target_os = "android")]
#[link_section = ".init_array"]
static INIT_ARRAY: [extern "C" fn(); 1] = [init_array_entry];

#[cfg(target_os = "android")]
extern "C" fn init_array_entry() {
    // 不在此处初始化，等待 entry() 被远程调用
}

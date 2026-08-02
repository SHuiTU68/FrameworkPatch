//! FKTee-rs 注入 payload 库
//!
//! 这个 .so 被 ptrace 注入到 keystore2 进程后，
//! entry() 函数会被远程调用。
//! 它负责：
//! 1. 初始化日志
//! 2. 读取 injector.toml 的 `[hook].enabled` 全局开关
//! 3. 从 allow.list 加载白名单
//! 4. 安装 binder ioctl PLT hook（自实现，不依赖 LSPlt）
//! 5. 对每个 binder 事务检查调用方 UID 是否在白名单中：
//!    - 在白名单中 → 对 attestation 事务进行伪造
//!    - 不在白名单中 → 透传原始事务

// 复用 hook.rs 的实现（统一一份 hook 代码）。
#[path = "hook.rs"]
mod hook;

use std::ffi::c_void;
use std::os::raw::c_int;
use std::path::Path;
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

    // 设置 hook 日志函数（复用 payload 的 __android_log_print）
    let log_fn = ANDROID_LOG_PRINT.load(std::sync::atomic::Ordering::Relaxed);
    if !log_fn.is_null() {
        hook::set_log_fn(log_fn);
    }

    // 加载白名单
    let allow_path = Path::new("/data/adb/Tee-rs/allow.list");
    if allow_path.exists() {
        hook::load_allow_list(allow_path);
        log_info(&format!("白名单已加载: {:?}", allow_path));
    } else {
        log_info("allow.list 不存在，所有应用透传（无伪造）");
        hook::load_allow_list(allow_path); // 会设置空白名单
    }

    // 安装 binder ioctl PLT hook（自实现，不依赖 LSPlt）
    match hook::init_hook() {
        Ok(()) => {
            log_info("FKTee-rs PLT hook 安装成功，开始按白名单拦截 keystore2 事务");
        }
        Err(e) => {
            log_error(&format!("PLT hook 安装失败: {e}"));
        }
    }
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
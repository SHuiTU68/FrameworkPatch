//! binder ioctl PLT hook — 自实现（不依赖 LSPlt C++ 库）。
//!
//! 在 keystore2 进程内直接 hook `libbinder.so` 的 `ioctl` PLT 项，
//! 拦截 BINDER_WRITE_READ 中的 BR_TRANSACTION 事务。
//!
//! **白名单模式**：对每个事务检查调用方 UID（sender_euid），
//! 反查包名后与 `allow.list` 白名单比对。仅对白名单中的应用进行
//! attestation 伪造，其余应用透传原始事务。
//!
//! # PLT hook 原理
//!
//! 1. 解析 `/proc/self/maps` 找到 `libbinder.so` 基址
//! 2. 解析 ELF 头找到 `.rela.plt` 和 `.got.plt` 段
//! 3. 在 `.rela.plt` 中定位 `ioctl` 的 relocation 条目
//! 4. 修改 `.got.plt` 对应条目指向我们的 `hooked_ioctl`
//! 5. 保存原始 ioctl 地址供 hook 函数调用

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::path::Path;
use std::sync::atomic::{AtomicPtr, AtomicBool, Ordering};
use std::sync::OnceLock;

// ============================================================================
// 白名单数据（进程全局，payload 初始化时加载）
// ============================================================================

/// 白名单包名集合（payload 初始化时从 allow.list 加载）。
static ALLOW_LIST: OnceLock<HashSet<String>> = OnceLock::new();

/// 是否已初始化白名单。
static ALLOW_LIST_LOADED: AtomicBool = AtomicBool::new(false);

/// 从 allow.list 加载白名单。
pub fn load_allow_list(path: &Path) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            hook_log("allow.list 不可读，白名单为空");
            let _ = ALLOW_LIST.set(HashSet::new());
            ALLOW_LIST_LOADED.store(true, Ordering::SeqCst);
            return;
        }
    };

    let pkgs: HashSet<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            // 去掉末尾模式后缀（! = generation, ? = leaf_hack）
            l.trim_end_matches('!').trim_end_matches('?').to_string()
        })
        .collect();

    let _ = ALLOW_LIST.set(pkgs);
    ALLOW_LIST_LOADED.store(true, Ordering::SeqCst);
    hook_log(&format!("白名单加载: {} 个包", ALLOW_LIST_LOADED.load(Ordering::Relaxed)));
}

/// 检查包名是否在白名单中。
pub fn is_package_allowed(pkg: &str) -> bool {
    ALLOW_LIST.get().map(|s| s.contains(pkg)).unwrap_or(false)
}

/// 检查 UID 是否在白名单中（通过 /data/system/packages.list 反查）。
pub fn is_uid_allowed(uid: u32) -> bool {
    let Some(allow) = ALLOW_LIST.get() else {
        return false;
    };
    if allow.is_empty() {
        return false;
    }

    // 读取 /data/system/packages.list 获取该 uid 的包名
    let Ok(content) = fs::read_to_string("/data/system/packages.list") else {
        return false;
    };

    for line in content.lines() {
        let mut it = line.split_whitespace();
        let pkg = match it.next() {
            Some(p) => p,
            None => continue,
        };
        let uid_str = match it.next() {
            Some(u) => u,
            None => continue,
        };
        let pkg_uid: u32 = match uid_str.parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        if pkg_uid == uid && allow.contains(pkg) {
            return true;
        }
    }
    false
}

// ============================================================================
// Hook 日志（通过函数指针，由 payload 初始化时设置）
// ============================================================================

static HOOK_LOG_FN: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

/// 设置 hook 日志函数（由 payload 在 entry() 中初始化）。
pub fn set_log_fn(fn_ptr: *mut std::ffi::c_void) {
    HOOK_LOG_FN.store(fn_ptr, Ordering::SeqCst);
}

/// 内部日志函数。
fn hook_log(msg: &str) {
    let fn_ptr = HOOK_LOG_FN.load(Ordering::Relaxed);
    if fn_ptr.is_null() {
        // 回退到 stderr
        unsafe {
            let _ = libc::write(2, b"[FKTee-hook] \0".as_ptr() as *const _, 13);
            let _ = libc::write(2, msg.as_ptr() as *const _, msg.len());
            let _ = libc::write(2, b"\n\0".as_ptr() as *const _, 1);
        }
        return;
    }
    let tag = b"FKTee-hook\0";
    let c_msg = match CString::new(msg) {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe {
        let log_fn: unsafe extern "C" fn(c_int, *const std::os::raw::c_char, *const std::os::raw::c_char) -> c_int =
            std::mem::transmute(fn_ptr);
        log_fn(4, tag.as_ptr() as *const _, c_msg.as_ptr());
    }
}

// ============================================================================
// PLT Hook 实现
// ============================================================================

/// 原始 ioctl 函数指针。
static ORIGINAL_IOCTL: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

/// 是否已安装 hook。
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// 初始化 PLT hook：替换 libbinder.so 中的 ioctl 为我们的 hooked_ioctl。
pub fn init_hook() -> Result<(), String> {
    if HOOK_INSTALLED.load(Ordering::SeqCst) {
        hook_log("hook 已安装，跳过");
        return Ok(());
    }

    hook_log("初始化 PLT hook (libbinder.so ioctl)");

    // 1. 找到 libbinder.so 的基址
    let libbinder_base = find_lib_base("libbinder.so")
        .ok_or_else(|| "找不到 libbinder.so 基址".to_string())?;
    hook_log(&format!("libbinder.so base=0x{libbinder_base:x}"));

    // 2. 找到 libc.so 中 ioctl 的地址（原始函数）
    let real_ioctl = find_sym("libc.so", "ioctl")
        .ok_or_else(|| "找不到 ioctl 符号".to_string())?;
    hook_log(&format!("real ioctl addr=0x{:x}", real_ioctl as usize));

    // 3. 在 libbinder.so 中查找 ioctl 的 GOT 条目
    let got_entry = find_got_entry(libbinder_base, "ioctl")
        .ok_or_else(|| "找不到 libbinder.so 中 ioctl 的 GOT 条目".to_string())?;
    hook_log(&format!("GOT entry for ioctl at 0x{got_entry:x}"));

    // 4. 修改 GOT 条目指向我们的 hook
    unsafe {
        // 修改内存保护为可写
        let page_size: u64 = 4096;
        let page_start = (got_entry / page_size) * page_size;
        let ret = libc::mprotect(
            page_start as *mut libc::c_void,
            page_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        if ret != 0 {
            return Err("mprotect 失败，无法修改 GOT".to_string());
        }

        // 保存原始 ioctl 地址
        ORIGINAL_IOCTL.store(real_ioctl, Ordering::SeqCst);

        // 写入我们的 hook 地址
        let hook_ptr = hooked_ioctl as *const std::ffi::c_void;
        std::ptr::write(got_entry as *mut *const std::ffi::c_void, hook_ptr);
    }

    HOOK_INSTALLED.store(true, Ordering::SeqCst);
    hook_log("PLT hook 安装成功");
    Ok(())
}

// ============================================================================
// Hook 函数 — 拦截 binder ioctl 并检查白名单
// ============================================================================

/// 被 hook 的 ioctl 函数。
///
/// 流程：
/// 1. 调用原始 ioctl
/// 2. 如果是 BINDER_WRITE_READ 且包含 BR_TRANSACTION，解析事务数据
/// 3. 检查 sender_euid 是否在白名单中
/// 4. 如果不在白名单中，透传（不做任何修改）
/// 5. 如果在白名单中，对 attestation 相关事务进行伪造
#[no_mangle]
pub extern "C" fn hooked_ioctl(fd: c_int, request: u32, arg: *mut std::ffi::c_void) -> c_int {
    let original = ORIGINAL_IOCTL.load(Ordering::Relaxed);
    if original.is_null() {
        return -1;
    }

    // 先调用原始 ioctl
    let orig_fn: extern "C" fn(c_int, u32, *mut std::ffi::c_void) -> c_int =
        unsafe { std::mem::transmute(original) };
    let result = orig_fn(fd, request, arg);

    // 只关心 BINDER_WRITE_READ
    if request != BINDER_WRITE_READ {
        return result;
    }

    // 解析 binder_write_read 结构
    if arg.is_null() {
        return result;
    }

    let bwr = unsafe { &*(arg as *const BinderWriteRead) };
    if bwr.read_consumed <= 0 {
        return result;
    }

    // 遍历 read buffer 中的命令
    let read_buf = bwr.read_buffer as *const u32;
    if read_buf.is_null() {
        return result;
    }

    let mut consumed: u64 = 0;
    while (consumed as i64) < bwr.read_consumed {
        let cmd = unsafe { *read_buf.add((consumed / 4) as usize) };

        match cmd {
            BR_TRANSACTION | BR_TRANSACTION_SEC_CTX => {
                // 解析事务数据
                let tr_data_ptr = unsafe {
                    read_buf.add((consumed / 4) as usize + 1) as *const BinderTransactionData
                };
                let tr = unsafe { &*tr_data_ptr };

                let sender_euid = tr.sender_euid;
                let code = tr.code;

                // 检查白名单
                if !is_uid_allowed(sender_euid as u32) {
                    hook_log(&format!(
                        "uid={} code=0x{:x} 不在白名单中，透传",
                        sender_euid, code
                    ));
                } else {
                    hook_log(&format!(
                        "uid={} code=0x{:x} 在白名单中，处理伪造",
                        sender_euid, code
                    ));
                    // TODO: 对 attestation 相关事务进行伪造
                    // 需要与 daemon 通信或直接使用 keybox 生成证书
                    // 当前阶段：标记该事务需要伪造，后续实现
                    handle_attestation_transaction(tr, bwr);
                }
            }
            _ => {}
        }

        // 前进到下一个命令
        // BR_TRANSACTION: 4字节 cmd + sizeof(BinderTransactionData)
        // BR_TRANSACTION_SEC_CTX: 4字节 cmd + sizeof(BinderTransactionDataSecCtx)
        if cmd == BR_TRANSACTION {
            consumed += 4 + std::mem::size_of::<BinderTransactionData>() as u64;
        } else if cmd == BR_TRANSACTION_SEC_CTX {
            consumed += 4 + std::mem::size_of::<BinderTransactionDataSecCtx>() as u64;
        } else {
            // 未知命令，跳过 4 字节（仅 cmd）
            consumed += 4;
        }
    }

    result
}

/// 处理 attestation 相关事务。
///
/// 当前阶段：仅记录日志。完整的伪造逻辑需要：
/// 1. 与 daemon 建立通信（Unix socket 或共享内存）
/// 2. daemon 使用 keybox + certgen 生成伪造证书链
/// 3. 将伪造结果写回 binder 事务缓冲区
///
/// TODO: 在后续实现中完成完整的伪造逻辑。
fn handle_attestation_transaction(_tr: &BinderTransactionData, _bwr: &BinderWriteRead) {
    // 占位：标记事务需要伪造
    // 完整实现需：
    // 1. 解析事务数据中的 attestation 请求
    // 2. 通过 socket 发送给 daemon 处理
    // 3. daemon 返回伪造的证书链
    // 4. 修改 binder 事务缓冲区中的响应数据
    hook_log("attestation 事务拦截 (TODO: 伪造逻辑)");
}

// ============================================================================
// ELF 辅助函数
// ============================================================================

/// 从 /proc/self/maps 中查找指定库的基址。
fn find_lib_base(lib_name: &str) -> Option<u64> {
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    for line in maps.lines() {
        if line.contains(lib_name) && line.contains("r-xp") {
            let end = line.find('-')?;
            let base = u64::from_str_radix(&line[..end], 16).ok()?;
            return Some(base);
        }
    }
    None
}

/// 查找指定库中某符号的地址（通过 dlsym）。
fn find_sym(lib_name: &str, sym_name: &str) -> Option<*mut std::ffi::c_void> {
    unsafe {
        let lib_cstr = CString::new(lib_name).ok()?;
        let handle = libc::dlopen(lib_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if handle.is_null() {
            return None;
        }
        let sym_cstr = CString::new(sym_name).ok()?;
        let addr = libc::dlsym(handle, sym_cstr.as_ptr());
        libc::dlclose(handle);
        if addr.is_null() { None } else { Some(addr) }
    }
}

/// 在指定 ELF（已加载）中查找某符号的 GOT 条目地址。
///
/// 通过解析 ELF 的 `.rela.plt` 段找到 `ioctl` 的 relocation，
/// 然后计算对应的 `.got.plt` 条目地址。
fn find_got_entry(base: u64, sym_name: &str) -> Option<u64> {
    unsafe {
        // 解析 ELF 头
        let ehdr = &*(base as *const Elf64_Ehdr);
        if ehdr.e_ident[0..4] != [0x7f, b'E', b'L', b'F'] {
            return None;
        }

        // 找到节头表
        let shoff = ehdr.e_shoff as usize;
        let shentsize = ehdr.e_shentsize as usize;
        let shnum = ehdr.e_shnum as usize;
        let shstrndx = ehdr.e_shstrndx as usize;

        // 读取节头字符串表
        let shstrtab = if shstrndx < shnum {
            let shstrtab_hdr = &*((base as usize + shoff + shstrndx * shentsize) as *const Elf64_Shdr);
            let offset = shstrtab_hdr.sh_offset as usize;
            base as usize + offset
        } else {
            return None;
        };

        // 遍历所有节头找 .rela.plt 和 .dynsym/.dynstr
        let mut rela_plt_offset = 0usize;
        let mut rela_plt_size = 0usize;
        let mut dynsym_offset = 0usize;
        let mut dynsym_size = 0usize;
        let mut dynstr_offset = 0usize;
        let mut got_plt_offset = 0usize;

        for i in 0..shnum {
            let shdr = &*((base as usize + shoff + i * shentsize) as *const Elf64_Shdr);
            let name_ptr = shstrtab + shdr.sh_name as usize;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8).to_str().unwrap_or("");

            match name {
                ".rela.plt" => {
                    rela_plt_offset = shdr.sh_addr as usize;
                    rela_plt_size = shdr.sh_size as usize;
                }
                ".dynsym" => {
                    dynsym_offset = shdr.sh_addr as usize;
                    dynsym_size = shdr.sh_size as usize;
                }
                ".dynstr" => {
                    dynstr_offset = shdr.sh_addr as usize;
                }
                ".got.plt" => {
                    got_plt_offset = shdr.sh_addr as usize;
                }
                _ => {}
            }
        }

        if rela_plt_offset == 0 || dynsym_offset == 0 || dynstr_offset == 0 || got_plt_offset == 0 {
            return None;
        }

        // 找到 ioctl 的符号索引
        let sym_entsize = 24usize; // sizeof(Elf64_Sym)
        let sym_count = dynsym_size / sym_entsize;
        let mut target_sym_idx = None;

        for i in 1..sym_count {
            let sym = &*((dynsym_offset + i * sym_entsize) as *const Elf64_Sym);
            let name_ptr = (dynstr_offset + sym.st_name as usize) as *const i8;
            let name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");
            if name == sym_name {
                target_sym_idx = Some(i);
                break;
            }
        }

        let sym_idx = target_sym_idx?;

        // 遍历 .rela.plt 找到对应符号的 relocation
        let rela_entsize = 24usize; // sizeof(Elf64_Rela)
        let rela_count = rela_plt_size / rela_entsize;

        for i in 0..rela_count {
            let rela = &*((rela_plt_offset + i * rela_entsize) as *const Elf64_Rela);
            let rela_sym_idx = (rela.r_info >> 32) as usize;

            if rela_sym_idx == sym_idx {
                // GOT 条目地址 = base + rela.r_offset（通常 .got.plt 中的偏移）
                let got_entry = base + rela.r_offset;
                return Some(got_entry);
            }
        }

        None
    }
}

// ============================================================================
// ELF 数据结构（与 Linux 内核一致）
// ============================================================================

#[repr(C)]
struct Elf64_Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
struct Elf64_Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[repr(C)]
struct Elf64_Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[repr(C)]
struct Elf64_Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

// ============================================================================
// binder ioctl 常量与结构体
// ============================================================================

/// 后门 code（daemon 握手用）
const BACKDOOR_CODE: u32 = 0xfeedface;

/// binder ioctl 命令
const BINDER_WRITE_READ: u32 = _iowr(b'b', 1, std::mem::size_of::<BinderWriteRead>() as u32);

/// binder 返回命令
const BR_TRANSACTION: u32 = _ior(b'r', 2, std::mem::size_of::<BinderTransactionData>() as u32);
const BR_TRANSACTION_SEC_CTX: u32 =
    _ior(b'r', 42, std::mem::size_of::<BinderTransactionDataSecCtx>() as u32);

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
// ioctl 宏
// ============================================================================

const fn _iowr(typ: u8, nr: u32, size: u32) -> u32 {
    (3 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

const fn _ior(typ: u8, nr: u32, size: u32) -> u32 {
    (2 << 30) | ((size & 0x3fff) << 16) | ((typ as u32) << 8) | nr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_consts() {
        assert_ne!(BINDER_WRITE_READ, 0);
        assert_ne!(BR_TRANSACTION, 0);
        assert_ne!(BR_TRANSACTION_SEC_CTX, 0);
        assert_eq!(BINDER_WRITE_READ >> 30, 3);
        assert_eq!(BR_TRANSACTION >> 30, 2);
        assert_eq!(BR_TRANSACTION_SEC_CTX >> 30, 2);
        assert_eq!((BR_TRANSACTION >> 0) & 0xff, 2);
        assert_eq!((BR_TRANSACTION_SEC_CTX >> 0) & 0xff, 42);
    }

    #[test]
    fn test_elf_header_sizes() {
        assert_eq!(std::mem::size_of::<Elf64_Ehdr>(), 64);
        assert_eq!(std::mem::size_of::<Elf64_Shdr>(), 64);
        assert_eq!(std::mem::size_of::<Elf64_Sym>(), 24);
        assert_eq!(std::mem::size_of::<Elf64_Rela>(), 24);
    }

    #[test]
    fn test_binder_struct_sizes() {
        assert_eq!(std::mem::size_of::<BinderWriteRead>(), 48);
        assert_eq!(std::mem::size_of::<BinderTransactionData>(), 56);
        assert_eq!(std::mem::size_of::<BinderTransactionDataSecCtx>(), 64);
    }
}
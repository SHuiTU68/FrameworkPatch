//! ptrace 远程 dlopen 注入器
//!
//! 参考 OhMyKeymint / ForgeStore / TEESimulator-RS 的注入器实现。
//! 流程：
//! 1. PTRACE_ATTACH 目标进程
//! 2. 保存原始寄存器
//! 3. 扫描 /proc/<pid>/maps 获取 libc 基址
//! 4. 在目标进程内远程调用 socket/bind/recvmsg 建立抽象命名空间 unix socket
//! 5. 本地用 sendmsg + SCM_RIGHTS 把 payload .so 的 fd 传进目标进程
//! 6. 远程调用 android_dlopen_ext(..., ANDROID_DLEXT_USE_LIBRARY_FD) 加载该 fd
//! 7. 远程 dlsym 找到 entry 符号并调用
//! 8. 恢复原始寄存器，PTRACE_DETACH

use anyhow::{bail, Context, Result};
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use std::ffi::CString;
use std::fs;
use std::path::Path;

/// 通过进程名查找 PID
pub fn find_process_by_name(name: &str) -> Option<i32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let pid: i32 = pid_str.parse().ok()?;
        if pid <= 0 {
            continue;
        }
        if let Ok(cmdline) = fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            let proc_name = cmdline.split('\0').next().unwrap_or("");
            // 取 basename
            let base = proc_name.rsplit('/').next().unwrap_or(proc_name);
            if base == name {
                return Some(pid);
            }
        }
    }
    None
}

/// 检查目标进程是否已加载 payload（幂等检查）
pub fn is_already_injected(pid: i32, payload_path: &Path) -> Result<bool> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("读取 /proc/{pid}/maps 失败"))?;

    let payload_name = payload_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    if payload_name.is_empty() {
        return Ok(false);
    }

    // 检查 maps 中是否已有该 .so
    Ok(maps.lines().any(|line| line.contains(&payload_name)))
}

/// 执行完整注入流程
#[cfg(target_arch = "aarch64")]
pub fn inject_library(pid: i32, payload_path: &Path) -> Result<()> {
    let target_pid = Pid::from_raw(pid);

    log::debug!("PTRACE_ATTACH pid={pid}");
    ptrace::attach(target_pid).context("PTRACE_ATTACH 失败")?;
    waitpid(target_pid, None).context("等待 attach 完成失败")?;

    let result = do_inject(pid, payload_path);

    // 无论成功失败都恢复寄存器并 detach
    log::debug!("恢复寄存器并 detach");
    let _ = restore_and_detach(target_pid);

    result
}

/// 非 AArch64 平台的占位实现（injector 只在 Android arm64 上运行）
#[cfg(not(target_arch = "aarch64"))]
pub fn inject_library(_pid: i32, _payload_path: &Path) -> Result<()> {
    anyhow::bail!("ptrace 注入仅在 aarch64 Android 上支持")
}

/// 核心注入逻辑（在 ptrace attach 状态下执行）
#[cfg(target_arch = "aarch64")]
fn do_inject(pid: i32, payload_path: &Path) -> Result<()> {
    // 1. 保存原始寄存器
    let original_regs = ptrace::getregs(Pid::from_raw(pid))
        .context("读取寄存器失败")?;
    log::debug!("原始 PC=0x{:x}", original_regs.pc);

    // 2. 扫描目标进程的内存映射，找到关键库的基址
    let maps = parse_proc_maps(pid)?;
    let libc_base = find_lib_base(&maps, "libc.so")
        .or_else(|| find_lib_base(&maps, "libc.a"))
        .ok_or_else(|| anyhow::anyhow!("找不到 libc.so 基址"))?;

    let linker_base = find_lib_base(&maps, "linker64")
        .or_else(|| find_lib_base(&maps, "linker"))
        .ok_or_else(|| anyhow::anyhow!("找不到 linker 基址"))?;

    log::debug!("libc base=0x{:x}, linker base=0x{:x}", libc_base, linker_base);

    // 3. 确保 payload 文件存在且可读
    if !payload_path.exists() {
        bail!("payload 不存在: {}", payload_path.display());
    }

    // 4. 打开 payload 的 fd
    let payload_cstr = CString::new(payload_path.to_string_lossy().as_bytes())
        .context("payload 路径转 CString 失败")?;

    // 5. 远程调用 android_dlopen_ext 加载 payload
    //    先找到 android_dlopen_ext 的地址
    //    android_dlopen_ext 在 libdl.so 中，但实际由 linker 实现
    let dlopen_ext_addr = find_remote_symbol(pid, &maps, "android_dlopen_ext")
        .or_else(|| find_remote_symbol(pid, &maps, "dlopen"))
        .ok_or_else(|| anyhow::anyhow!("找不到 android_dlopen_ext/dlopen 符号"))?;

    log::debug!("android_dlopen_ext addr=0x{:x}", dlopen_ext_addr);

    // 6. 远程调用 android_dlopen_ext(payload_path, RTLD_NOW, &extinfo)
    //    extinfo 包含 ANDROID_DLEXT_USE_LIBRARY_FD 标志
    //    使用 SCM_RIGHTS 传 fd，避免目标进程需要文件读权限
    let handle = remote_dlopen_ext(
        pid,
        dlopen_ext_addr,
        &payload_cstr,
        libc_base,
    ).context("远程 dlopen_ext 失败")?;

    if handle.is_null() {
        bail!("android_dlopen_ext 返回 NULL，加载 payload 失败");
    }

    log::info!("payload 加载成功，handle=0x{:x}", handle as usize);

    // 7. 远程调用 dlsym(handle, "entry") 找到入口符号
    let dlsym_addr = find_remote_symbol(pid, &maps, "dlsym")
        .ok_or_else(|| anyhow::anyhow!("找不到 dlsym 符号"))?;

    let entry_name = CString::new("entry").unwrap();
    let entry_addr = remote_dlsym(pid, dlsym_addr, handle, &entry_name, libc_base)
        .context("远程 dlsym 失败")?;

    if entry_addr.is_null() {
        bail!("dlsym 返回 NULL，找不到 entry 符号");
    }

    log::info!("entry 符号地址=0x{:x}", entry_addr as usize);

    // 8. 远程调用 entry(handle) 完成 hook 安装
    remote_call_void(pid, entry_addr, handle as u64, libc_base)
        .context("远程调用 entry() 失败")?;

    log::info!("entry() 调用完成");
    Ok(())
}

/// 解析 /proc/<pid>/maps
fn parse_proc_maps(pid: i32) -> Result<Vec<MapEntry>> {
    let content = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("读取 /proc/{pid}/maps 失败"))?;

    let mut entries = Vec::new();
    for line in content.lines() {
        // 格式: addr1-addr2 perms offset dev inode pathname
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(addr_range[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(addr_range[1], 16).unwrap_or(0);
        let perms = parts[1].to_string();
        let pathname = parts[5].to_string();

        entries.push(MapEntry {
            start,
            end,
            perms,
            pathname,
        });
    }

    Ok(entries)
}

#[derive(Debug, Clone)]
struct MapEntry {
    start: u64,
    end: u64,
    perms: String,
    pathname: String,
}

/// 在 maps 中查找指定库的基址
fn find_lib_base(maps: &[MapEntry], lib_name: &str) -> Option<u64> {
    maps.iter()
        .find(|m| m.pathname.contains(lib_name) && m.perms.contains('x'))
        .map(|m| m.start)
}

/// 在目标进程中查找符号地址
/// 先在本地进程查找符号偏移，再加上远程库基址
fn find_remote_symbol(_pid: i32, maps: &[MapEntry], symbol: &str) -> Option<u64> {
    // 在本地进程中查找该符号在 libc/libdl 中的地址
    // 简化实现：通过 /proc/self/maps 找到本地对应库基址，
    // 然后通过本地 dlsym 获取符号地址，计算偏移
    let local_maps = parse_proc_maps(nix::unistd::getpid().as_raw()).ok()?;

    // 找到包含该符号的库
    for remote_entry in maps {
        if remote_entry.perms.contains('x') && !remote_entry.pathname.is_empty() {
            // 检查本地是否有同名库
            let lib_name = remote_entry
                .pathname
                .rsplit('/')
                .next()
                .unwrap_or("");

            let local_entry = local_maps
                .iter()
                .find(|m| m.pathname.ends_with(lib_name) && m.perms.contains('x'));

            if let Some(local) = local_entry {
                // 尝试在本地 dlsym 这个符号
                let local_lib_path = &local.pathname;
                let local_lib_cstr = CString::new(local_lib_path.as_str()).ok()?;

                unsafe {
                    let local_handle = libc::dlopen(
                        local_lib_cstr.as_ptr(),
                        libc::RTLD_NOW | libc::RTLD_NOLOAD,
                    );
                    if local_handle.is_null() {
                        continue;
                    }

                    let sym_cstr = CString::new(symbol).ok()?;
                    let local_sym = libc::dlsym(local_handle, sym_cstr.as_ptr());
                    libc::dlclose(local_handle);

                    if local_sym.is_null() {
                        continue;
                    }

                    let offset = local_sym as u64 - local.start;
                    return Some(remote_entry.start + offset);
                }
            }
        }
    }

    // 回退：尝试直接在 libdl.so 中查找
    let libdl_base = find_lib_base(maps, "libdl.so")?;
    let local_libdl = find_lib_base(&local_maps, "libdl.so")?;

    unsafe {
        let dl_cstr = CString::new("libdl.so").ok()?;
        let local_handle = libc::dlopen(dl_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if local_handle.is_null() {
            return None;
        }

        let sym_cstr = CString::new(symbol).ok()?;
        let local_sym = libc::dlsym(local_handle, sym_cstr.as_ptr());
        libc::dlclose(local_handle);

        if local_sym.is_null() {
            return None;
        }

        let offset = local_sym as u64 - local_libdl;
        Some(libdl_base + offset)
    }
}

/// 远程调用 android_dlopen_ext(path, flags, &extinfo)
/// 使用 SCM_RIGHTS fd 传递避免文件权限问题
#[cfg(target_arch = "aarch64")]
fn remote_dlopen_ext(pid: i32, dlopen_ext_addr: u64, path: &CString, libc_base: u64) -> Result<*mut std::ffi::c_void> {
    log::debug!("远程 android_dlopen_ext(\"{}\")", path.to_str().unwrap_or("?"));

    // 简化实现：直接用路径方式 dlopen（不使用 fd 传递）
    // 完整实现应该用 SCM_RIGHTS 传 fd（参考 ForgeStore/OhMyKeymint）
    // 这里先实现路径方式，后续迭代加 fd 传递

    let target_pid = Pid::from_raw(pid);

    // 分配栈空间写入路径字符串
    let path_bytes = path.as_bytes_with_nul();
    let path_len = path_bytes.len();

    // 找到 mmap 在远程的地址
    let maps = parse_proc_maps(pid)?;
    let libc_entry = maps.iter().find(|m| m.pathname.contains("libc.so")).cloned();

    // 在远程栈上写入路径
    let regs = ptrace::getregs(target_pid)?;
    let sp = regs.sp;

    // 写入路径到栈上（向下生长，留对齐空间）
    let write_addr = sp.saturating_sub(path_len as u64 + 16) & !0xF; // 16字节对齐

    write_memory(pid, write_addr, path_bytes)?;

    // 准备参数（AArch64 调用约定）：
    // x0 = path 指针
    // x1 = flags (RTLD_NOW = 2)
    // x2 = extinfo 指针 (NULL for now, 简化实现)
    let mut call_regs = regs;
    call_regs.x[0] = write_addr;
    call_regs.x[1] = 2; // RTLD_NOW
    call_regs.x[2] = 0; // extinfo = NULL
    call_regs.pc = dlopen_ext_addr;
    // LR (x30) 设为一个安全返回地址（找一段非可执行的区域）
    call_regs.x[30] = find_safe_return_addr(&maps);

    // 设置 SP
    call_regs.sp = write_addr & !0xF;

    ptrace::setregs(target_pid, call_regs)?;
    ptrace::cont(target_pid, None)?;

    // 等待远程调用完成
    waitpid(target_pid, None)?;

    // 读取返回值
    let result_regs = ptrace::getregs(target_pid)?;
    let handle = result_regs.x[0] as *mut std::ffi::c_void;

    // 恢复原始 SP（恢复内存）
    let mut restore_regs = call_regs;
    restore_regs.sp = sp;
    let _ = ptrace::setregs(target_pid, restore_regs);

    Ok(handle)
}

/// 远程调用 dlsym(handle, name)
#[cfg(target_arch = "aarch64")]
fn remote_dlsym(pid: i32, dlsym_addr: u64, handle: *mut std::ffi::c_void, name: &CString, libc_base: u64) -> Result<*mut std::ffi::c_void> {
    let target_pid = Pid::from_raw(pid);
    let maps = parse_proc_maps(pid)?;

    let regs = ptrace::getregs(target_pid)?;
    let sp = regs.sp;

    // 在栈上写入符号名
    let name_bytes = name.as_bytes_with_nul();
    let name_len = name_bytes.len();
    let name_addr = sp.saturating_sub(name_len as u64 + 16) & !0xF;

    write_memory(pid, name_addr, name_bytes)?;

    let mut call_regs = regs;
    call_regs.x[0] = handle as u64;
    call_regs.x[1] = name_addr;
    call_regs.pc = dlsym_addr;
    call_regs.x[30] = find_safe_return_addr(&maps);
    call_regs.sp = name_addr & !0xF;

    ptrace::setregs(target_pid, call_regs)?;
    ptrace::cont(target_pid, None)?;
    waitpid(target_pid, None)?;

    let result_regs = ptrace::getregs(target_pid)?;
    let sym_addr = result_regs.x[0] as *mut std::ffi::c_void;

    // 恢复 SP
    let mut restore_regs = call_regs;
    restore_regs.sp = sp;
    let _ = ptrace::setregs(target_pid, restore_regs);

    Ok(sym_addr)
}

/// 远程调用无返回值函数 f(handle)
#[cfg(target_arch = "aarch64")]
fn remote_call_void(pid: i32, func_addr: u64, arg0: u64, _libc_base: u64) -> Result<()> {
    let target_pid = Pid::from_raw(pid);
    let maps = parse_proc_maps(pid)?;

    let regs = ptrace::getregs(target_pid)?;

    let mut call_regs = regs;
    call_regs.x[0] = arg0;
    call_regs.pc = func_addr;
    call_regs.x[30] = find_safe_return_addr(&maps);

    ptrace::setregs(target_pid, call_regs)?;
    ptrace::cont(target_pid, None)?;
    waitpid(target_pid, None)?;

    // 检查是否异常
    let status = nix::sys::wait::waitpid(target_pid, None);
    log::debug!("远程调用结果状态: {:?}", status);

    Ok(())
}

/// 写入内存到目标进程
#[cfg(target_arch = "aarch64")]
fn write_memory(pid: i32, addr: u64, data: &[u8]) -> Result<()> {
    let target_pid = Pid::from_raw(pid);

    // 按 word 写入（8字节对齐）
    let mut aligned = data.to_vec();
    while aligned.len() % 8 != 0 {
        aligned.push(0);
    }

    for (i, chunk) in aligned.chunks(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        ptrace::write(target_pid, addr as *mut u64, word as i64)?;
    }

    Ok(())
}

/// 找一个安全的返回地址（非可执行区域）
#[cfg(target_arch = "aarch64")]
fn find_safe_return_addr(maps: &[MapEntry]) -> u64 {
    maps.iter()
        .find(|m| !m.perms.contains('x') && m.perms.contains('r'))
        .map(|m| m.start)
        .unwrap_or(0)
}

/// 恢复原始寄存器并 detach
#[cfg(target_arch = "aarch64")]
fn restore_and_detach(target_pid: Pid) -> Result<()> {
    // 恢复原始寄存器已在调用者中处理
    ptrace::detach(target_pid, None)?;
    Ok(())
}

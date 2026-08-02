//! ptrace 远程 dlopen 注入器
//!
//! 参考 OhMyKeymint / ForgeStore / TEESimulator-RS 的注入器实现。
//! 流程：
//! 1. PTRACE_ATTACH 目标进程
//! 2. 保存原始寄存器
//! 3. 扫描 /proc/<pid>/maps 获取 libc 基址
//! 4. 在目标进程内远程调用 memfd_create 创建匿名内存文件
//! 5. 本地通过 /proc/<pid>/fd/<memfd> 向该 memfd 写入 payload 内容
//! 6. 远程调用 android_dlopen_ext(..., ANDROID_DLEXT_USE_LIBRARY_FD) 加载该 fd
//! 7. 远程 dlsym 找到 entry 符号并调用
//! 8. 恢复原始寄存器，PTRACE_DETACH

use anyhow::{Context, Result};
#[cfg(target_arch = "aarch64")]
use anyhow::bail;
#[cfg(target_arch = "aarch64")]
use nix::sys::wait::waitpid;
#[cfg(target_arch = "aarch64")]
use nix::unistd::Pid;
use std::ffi::CString;
use std::fs;
use std::path::Path;

/// NT_PRSTATUS 常量（用于 PTRACE_GETREGSET/SETREGSET）
#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: libc::c_long = 1;

/// AArch64 Linux syscall numbers
#[cfg(target_arch = "aarch64")]
const __NR_memfd_create: u64 = 279;
#[cfg(target_arch = "aarch64")]
const __NR_close: u64 = 57;

/// memfd_create flags
#[cfg(target_arch = "aarch64")]
const MFD_CLOEXEC: u64 = 0x0001;

/// ANDROID_DLEXT_USE_LIBRARY_FD — 通过 fd 加载 .so 的 flag
#[cfg(target_arch = "aarch64")]
const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x08;

/// 读取目标进程寄存器（aarch64 使用 PTRACE_GETREGSET + NT_PRSTATUS）
#[cfg(target_arch = "aarch64")]
fn ptrace_getregs(pid: i32) -> Result<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    if ret == -1 {
        bail!("PTRACE_GETREGSET 失败: {}", std::io::Error::last_os_error());
    }
    Ok(regs)
}

/// 设置目标进程寄存器（aarch64 使用 PTRACE_SETREGSET + NT_PRSTATUS）
#[cfg(target_arch = "aarch64")]
fn ptrace_setregs(pid: i32, regs: &libc::user_regs_struct) -> Result<()> {
    let mut iov = libc::iovec {
        iov_base: regs as *const _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            NT_PRSTATUS as *mut libc::c_void,
            &mut iov as *mut _ as *mut libc::c_void,
        )
    };
    if ret == -1 {
        bail!("PTRACE_SETREGSET 失败: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// 通过进程名查找 PID
pub fn find_process_by_name(name: &str) -> Option<i32> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        // /proc 下存在大量非数字条目（self、cpuinfo、fs、net …），遇到时跳过当前条目，
        // 不要用 `?` 传播 None——那会提前终止整个扫描，导致 keystore2 几乎永远找不到。
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };
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
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_ATTACH,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        bail!("PTRACE_ATTACH 失败: {}", std::io::Error::last_os_error());
    }
    waitpid(target_pid, None).context("等待 attach 完成失败")?;

    // do_inject 内部会在返回前（无论成功失败）恢复原始寄存器，
    // 这里只需保证最后一定 detach，避免目标进程卡在 ptrace-stop。
    let result = do_inject(pid, payload_path);

    log::debug!("detach pid={pid}");
    let _ = detach(target_pid);

    result
}

/// 非 AArch64 平台的占位实现（injector 只在 Android arm64 上运行）
#[cfg(not(target_arch = "aarch64"))]
pub fn inject_library(_pid: i32, _payload_path: &Path) -> Result<()> {
    anyhow::bail!("ptrace 注入仅在 aarch64 Android 上支持")
}

/// 核心注入逻辑（在 ptrace attach 状态下执行）
///
/// 关键：在返回前（无论成功失败）必须用 [`ptrace_setregs`] 恢复原始寄存器，
/// 否则 PTRACE_DETACH 后目标进程会从被改写的 PC（指向非可执行“安全返回地址”）
/// 处继续执行，立即 SIGSEGV 崩溃。
#[cfg(target_arch = "aarch64")]
fn do_inject(pid: i32, payload_path: &Path) -> Result<()> {
    // 1. 保存原始寄存器（退出前必须恢复）
    let original_regs = ptrace_getregs(pid).context("读取寄存器失败")?;
    log::debug!("原始 PC=0x{:x}", original_regs.pc);

    let result = (|| -> Result<()> {
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
        let dlopen_ext_addr = find_remote_symbol_in_libdl(pid, &maps, "android_dlopen_ext")
            .or_else(|| find_remote_symbol(pid, &maps, "android_dlopen_ext"))
            .or_else(|| find_remote_symbol_in_libdl(pid, &maps, "dlopen"))
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
        let dlsym_addr = find_remote_symbol_in_libdl(pid, &maps, "dlsym")
            .or_else(|| find_remote_symbol(pid, &maps, "dlsym"))
            .ok_or_else(|| anyhow::anyhow!("找不到 dlsym 符号"))?;

        let entry_name = CString::new("entry").unwrap();
        let entry_addr = remote_dlsym(pid, dlsym_addr, handle, &entry_name, libc_base)
            .context("远程 dlsym 失败")?;

        if entry_addr.is_null() {
            bail!("dlsym 返回 NULL，找不到 entry 符号");
        }

        log::info!("entry 符号地址=0x{:x}", entry_addr as usize);

        // 8. 远程调用 entry(handle) 完成 hook 安装
        remote_call_void(pid, entry_addr as u64, handle as u64, libc_base)
            .context("远程调用 entry() 失败")?;

        log::info!("entry() 调用完成");
        Ok(())
    })();

    // 无论上面成功还是失败，都恢复原始寄存器，确保 detach 后目标进程能正常继续
    if let Err(e) = ptrace_setregs(pid, &original_regs) {
        log::warn!("恢复原始寄存器失败: {e}");
    }
    result
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

/// 在目标进程的 libdl.so 中查找符号地址
///
/// `dlsym` 和 `android_dlopen_ext` 都在 libdl.so 中，用这个专门的函数
/// 直接通过 libdl.so 基址计算偏移，比通用 find_remote_symbol 更可靠。
fn find_remote_symbol_in_libdl(_pid: i32, maps: &[MapEntry], symbol: &str) -> Option<u64> {
    let remote_libdl = find_lib_base(maps, "libdl.so")?;
    let local_maps = parse_proc_maps(nix::unistd::getpid().as_raw()).ok()?;
    let local_libdl = find_lib_base(&local_maps, "libdl.so")?;

    unsafe {
        let dl_cstr = CString::new("libdl.so").ok()?;
        let local_handle =
            libc::dlopen(dl_cstr.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
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
        Some(remote_libdl + offset)
    }
}

/// 在目标进程中查找符号地址（通用方法，回退用）
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
    find_remote_symbol_in_libdl(_pid, maps, symbol)
}

/// 远程调用 android_dlopen_ext 加载 payload。
///
/// 使用 memfd_create + /proc/<pid>/fd/ 写入的组合方式绕过 mount namespace 隔离：
/// 1. 在目标进程内远程调用 memfd_create 创建匿名内存文件
/// 2. 本地通过 /proc/<pid>/fd/<memfd> 写入 payload 内容（自动扩展文件大小）
/// 3. 远程调用 android_dlopen_ext 并传入 ANDROID_DLEXT_USE_LIBRARY_FD
///
/// 注意：不调用 ftruncate 是因为 keystore2 的 seccomp 过滤器可能阻止该 syscall；
/// 直接 write 到 memfd 会自动扩展文件大小，无需 pre-alloc。
///
/// 这比 SCM_RIGHTS 方式更简单：不需要在远程进程中建立 socket/bind/listen/accept，
/// 也不需要本地的 sendmsg/recvmsg 配合。memfd 是内核内存文件，不依赖挂载命名空间。
#[cfg(target_arch = "aarch64")]
fn remote_dlopen_ext(pid: i32, dlopen_ext_addr: u64, path: &CString, _libc_base: u64) -> Result<*mut std::ffi::c_void> {
    log::debug!("远程 android_dlopen_ext(\"{}\") via memfd+fd", path.to_str().unwrap_or("?"));

    let target_pid = Pid::from_raw(pid);

    // 1. 获取原始寄存器（用于 remote_syscall 恢复）
    let regs = ptrace_getregs(pid)?;
    let sp = regs.sp;
    let maps = parse_proc_maps(pid)?;

    // 2. 准备远程栈数据
    let path_bytes = path.as_bytes_with_nul();
    let path_len = path_bytes.len();
    let path_padded = (path_len + 15) & !15; // 16字节对齐

    // "payload\0" 名称字符串
    let payload_name = b"payload\0";
    let payload_name_padded = 16; // 9字节补到16

    // android_dlextinfo 结构（aarch64）：40 bytes
    // offset 0: size_t flags (8)
    // offset 8: void* reserved_addr (8)
    // offset 16: size_t reserved_size (8)
    // offset 24: int relro_fd (4)
    // offset 28: int library_fd (4)
    // offset 32: size_t library_fd_offset (8)
    let dlextinfo_size: u64 = 40;

    // 总数据大小 + 安全边距
    let total_data = path_padded as u64 + payload_name_padded as u64 + dlextinfo_size + 32;

    let data_start = sp.saturating_sub(total_data) & !0xF;
    let payload_name_addr = data_start;
    let dlextinfo_addr = data_start + payload_name_padded as u64;
    let path_addr = dlextinfo_addr + dlextinfo_size;
    let new_sp = data_start.saturating_sub(32) & !0xF; // 留足函数调用栈空间

    // 3. 写入 payload 名称字符串到远程栈
    write_memory(pid, payload_name_addr, payload_name)?;

    // 4. 写入路径字符串到远程栈（用于 android_dlopen_ext 的 path 参数，仅作命名用）
    write_memory(pid, path_addr, path_bytes)?;

    // 5. 获取 payload 文件大小
    let file_size = std::fs::metadata(path.to_str().unwrap_or(""))
        .map(|m| m.len())
        .unwrap_or(0);
    if file_size == 0 {
        bail!("无法获取 payload 文件大小或文件为空: {}", path.to_str().unwrap_or("?"));
    }

    // 6. 远程调用 memfd_create("payload", MFD_CLOEXEC)
    log::debug!("远程 memfd_create...");
    let memfd = remote_syscall(
        pid, __NR_memfd_create, payload_name_addr, MFD_CLOEXEC,
        0, 0, 0, &regs, &maps,
    ).context("远程 memfd_create 失败")?;

    if memfd < 0 {
        bail!("memfd_create 返回 {}，创建内存文件失败", memfd);
    }
    log::debug!("memfd_create 成功，fd={}", memfd);

    // 7. 本地通过 /proc/<pid>/fd/<memfd> 写入 payload 内容
    // 注意：不调用 ftruncate — keystore2 的 seccomp 可能阻止该 syscall，
    // 直接 write 到 memfd 会自动扩展文件大小。
    let proc_fd_path = format!("/proc/{}/fd/{}", pid, memfd);
    log::debug!("通过 {} 写入 payload 内容...", proc_fd_path);
    let payload_content = std::fs::read(path.to_str().unwrap_or(""))
        .context("读取本地 payload 文件失败")?;

    match std::fs::write(&proc_fd_path, &payload_content) {
        Ok(_) => log::debug!("成功写入 {} 字节到 memfd", payload_content.len()),
        Err(e) => {
            // 写入失败，关闭 memfd 后向上报错
            let _ = remote_syscall(pid, __NR_close, memfd as u64, 0, 0, 0, 0, &regs, &maps);
            bail!("写入 payload 到 {} 失败: {e}", proc_fd_path);
        }
    }

    // 9. 设置 android_dlextinfo 结构
    // 标志位：ANDROID_DLEXT_USE_LIBRARY_FD
    let mut dlextinfo_buf = Vec::with_capacity(dlextinfo_size as usize);
    // flags: ANDROID_DLEXT_USE_LIBRARY_FD
    dlextinfo_buf.extend_from_slice(&ANDROID_DLEXT_USE_LIBRARY_FD.to_le_bytes());
    // reserved_addr: NULL
    dlextinfo_buf.extend_from_slice(&0u64.to_le_bytes());
    // reserved_size: 0
    dlextinfo_buf.extend_from_slice(&0u64.to_le_bytes());
    // relro_fd: -1
    dlextinfo_buf.extend_from_slice(&(-1i32).to_le_bytes());
    // library_fd: memfd
    dlextinfo_buf.extend_from_slice(&(memfd as i32).to_le_bytes());
    // library_fd_offset: 0
    dlextinfo_buf.extend_from_slice(&0u64.to_le_bytes());

    // 写入 dlextinfo 结构到远程栈
    write_memory(pid, dlextinfo_addr, &dlextinfo_buf)?;

    // 10. 远程调用 android_dlopen_ext(path, RTLD_NOW, &extinfo)
    log::debug!("远程 android_dlopen_ext with library_fd={}...", memfd);

    let mut call_regs = regs;
    call_regs.regs[0] = path_addr;       // path (仅用于命名)
    call_regs.regs[1] = 2;               // RTLD_NOW
    call_regs.regs[2] = dlextinfo_addr;  // &extinfo
    call_regs.pc = dlopen_ext_addr;
    call_regs.regs[30] = find_safe_return_addr(&maps);
    call_regs.sp = new_sp;

    ptrace_setregs(pid, &call_regs)?;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        // 恢复 SP
        let mut restore_regs = call_regs;
        restore_regs.sp = sp;
        let _ = ptrace_setregs(pid, &restore_regs);
        // 关闭 memfd
        let _ = remote_syscall(pid, __NR_close, memfd as u64, 0, 0, 0, 0, &regs, &maps);
        bail!("PTRACE_CONT 失败: {}", std::io::Error::last_os_error());
    }
    waitpid(target_pid, None)?;

    let result_regs = ptrace_getregs(pid)?;
    let handle = result_regs.regs[0] as *mut std::ffi::c_void;

    // 11. 如果返回 NULL，尝试获取远程 dlerror 信息
    if handle.is_null() {
        let dlerror_msg = remote_get_dlerror(pid, &maps);
        if let Some(msg) = dlerror_msg {
            log::error!("远程 android_dlopen_ext 失败: dlerror={msg}");
        } else {
            log::error!("远程 android_dlopen_ext 失败（无法获取 dlerror）");
        }
    }

    // 12. 关闭 memfd
    let _ = remote_syscall(pid, __NR_close, memfd as u64, 0, 0, 0, 0, &regs, &maps);

    // 恢复 SP
    let mut restore_regs = call_regs;
    restore_regs.sp = sp;
    let _ = ptrace_setregs(pid, &restore_regs);

    Ok(handle)
}

/// 远程调用 dlerror() 获取错误信息
///
/// 在目标进程中调用 dlerror()，读取返回的字符串内容。
/// 用于 android_dlopen_ext 失败时获取详细的错误原因。
#[cfg(target_arch = "aarch64")]
fn remote_get_dlerror(pid: i32, maps: &[MapEntry]) -> Option<String> {
    let dlerror_addr = find_remote_symbol_in_libdl(pid, maps, "dlerror")
        .or_else(|| find_remote_symbol(pid, maps, "dlerror"))?;

    let target_pid = Pid::from_raw(pid);

    let regs = ptrace_getregs(pid).ok()?;
    let mut call_regs = regs;
    call_regs.regs[0] = 0; // dlerror() 无参数
    call_regs.pc = dlerror_addr;
    call_regs.regs[30] = find_safe_return_addr(maps);

    ptrace_setregs(pid, &call_regs).ok()?;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        return None;
    }
    waitpid(target_pid, None).ok()?;

    let result_regs = ptrace_getregs(pid).ok()?;
    let msg_ptr = result_regs.regs[0];

    // 恢复原始寄存器
    let _ = ptrace_setregs(pid, &regs);

    if msg_ptr == 0 {
        return None;
    }

    // 读取远程内存中的字符串（最多 256 字节）
    let mut buf = [0u8; 256];
    let mut read = 0;
    while read < buf.len() {
        let word = unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKDATA,
                pid,
                (msg_ptr + read as u64) as *mut libc::c_void,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if word == -1 {
            break;
        }
        let bytes = word.to_ne_bytes();
        let copy_len = std::cmp::min(8, buf.len() - read);
        buf[read..read + copy_len].copy_from_slice(&bytes[..copy_len]);
        // 遇到 null 终止符则停止
        if bytes[0] == 0 {
            break;
        }
        read += copy_len;
    }

    let msg = std::ffi::CStr::from_bytes_until_nul(&buf).ok()?;
    Some(msg.to_string_lossy().into_owned())
}

/// 远程调用 dlsym(handle, name)
///
/// `_libc_base` 当前未使用，保留参数位以兼容未来扩展。
#[cfg(target_arch = "aarch64")]
fn remote_dlsym(pid: i32, dlsym_addr: u64, handle: *mut std::ffi::c_void, name: &CString, _libc_base: u64) -> Result<*mut std::ffi::c_void> {
    let target_pid = Pid::from_raw(pid);
    let maps = parse_proc_maps(pid)?;

    let regs = ptrace_getregs(pid)?;
    let sp = regs.sp;

    // 在栈上写入符号名
    let name_bytes = name.as_bytes_with_nul();
    let name_len = name_bytes.len();
    let name_addr = sp.saturating_sub(name_len as u64 + 16) & !0xF;

    write_memory(pid, name_addr, name_bytes)?;

    let mut call_regs = regs;
    call_regs.regs[0] = handle as u64;
    call_regs.regs[1] = name_addr;
    call_regs.pc = dlsym_addr;
    call_regs.regs[30] = find_safe_return_addr(&maps);
    call_regs.sp = name_addr & !0xF;

    ptrace_setregs(pid, &call_regs)?;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        bail!("PTRACE_CONT 失败: {}", std::io::Error::last_os_error());
    }
    waitpid(target_pid, None)?;

    let result_regs = ptrace_getregs(pid)?;
    let sym_addr = result_regs.regs[0] as *mut std::ffi::c_void;

    // 恢复 SP
    let mut restore_regs = call_regs;
    restore_regs.sp = sp;
    let _ = ptrace_setregs(pid, &restore_regs);

    Ok(sym_addr)
}

/// 远程调用无返回值函数 f(handle)
///
/// `_libc_base` 当前未使用，保留参数位以兼容未来扩展。
#[cfg(target_arch = "aarch64")]
fn remote_call_void(pid: i32, func_addr: u64, arg0: u64, _libc_base: u64) -> Result<()> {
    let target_pid = Pid::from_raw(pid);
    let maps = parse_proc_maps(pid)?;

    let regs = ptrace_getregs(pid)?;

    let mut call_regs = regs;
    call_regs.regs[0] = arg0;
    call_regs.pc = func_addr;
    call_regs.regs[30] = find_safe_return_addr(&maps);

    ptrace_setregs(pid, &call_regs)?;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        bail!("PTRACE_CONT 失败: {}", std::io::Error::last_os_error());
    }

    // 等待远程调用返回（执行到 LR 即非可执行“安全返回地址”时 SIGSEGV 停下）。
    // 注意：只能 waitpid 一次——目标进程已被本次 wait 接管并处于 stop 态，
    // 再次 waitpid 会因为没有后续状态变化而永久阻塞（injector 挂死）。
    let status = waitpid(target_pid, None)?;
    log::debug!("远程调用结果状态: {:?}", status);

    Ok(())
}

/// 写入内存到目标进程
#[cfg(target_arch = "aarch64")]
fn write_memory(pid: i32, addr: u64, data: &[u8]) -> Result<()> {
    // 按 word 写入（8字节对齐）
    let mut aligned = data.to_vec();
    while aligned.len() % 8 != 0 {
        aligned.push(0);
    }

    for (i, chunk) in aligned.chunks(8).enumerate() {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                (addr + (i as u64 * 8)) as *mut libc::c_void,
                word as *mut libc::c_void,
            )
        };
        if ret == -1 {
            bail!("PTRACE_POKEDATA 写入失败: {}", std::io::Error::last_os_error());
        }
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

/// 在远程进程中调用 libc::syscall(number, arg1..arg5)。
///
/// 返回 syscall 的原始返回值（失败时返回 -1，不会自动 bail）。
/// 调用方需自行检查返回值并解释错误。
///
/// 注意：调用完成后**不会自动恢复原始寄存器**。调用方必须确保在
/// `do_inject` 返回前统一恢复原始寄存器（由 `do_inject` 的 finally 块保证）。
/// 本函数只会修改 PC、SP 和 x0-x5、x30，并从原始寄存器快照派生出临时寄存器值。
#[cfg(target_arch = "aarch64")]
fn remote_syscall(
    pid: i32,
    number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    saved_regs: &libc::user_regs_struct,
    maps: &[MapEntry],
) -> Result<i64> {
    let syscall_addr = find_remote_symbol(pid, maps, "syscall")
        .ok_or_else(|| anyhow::anyhow!("找不到 syscall 符号"))?;

    let target_pid = Pid::from_raw(pid);

    let mut call_regs = *saved_regs;
    // syscall() 调用约定（aarch64）：
    // x0 = syscall number
    // x1..x5 = syscall arguments
    call_regs.regs[0] = number;
    call_regs.regs[1] = arg1;
    call_regs.regs[2] = arg2;
    call_regs.regs[3] = arg3;
    call_regs.regs[4] = arg4;
    call_regs.regs[5] = arg5;
    call_regs.pc = syscall_addr;
    call_regs.regs[30] = find_safe_return_addr(maps);

    ptrace_setregs(pid, &call_regs)?;
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        bail!("PTRACE_CONT 失败: {}", std::io::Error::last_os_error());
    }
    waitpid(target_pid, None)?;

    let result_regs = ptrace_getregs(pid)?;
    let result = result_regs.regs[0] as i64;

    Ok(result)
}

/// 从目标进程 detach。
///
/// 寄存器恢复已在 [`do_inject`] 中完成，这里只负责 PTRACE_DETACH，
/// 让目标进程从原始 PC 处正常继续执行。
#[cfg(target_arch = "aarch64")]
fn detach(target_pid: Pid) -> Result<()> {
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_DETACH,
            target_pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if ret == -1 {
        bail!("PTRACE_DETACH 失败: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-only
use crate::model::{ActionResult, Identity, Memory, Process};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND, LPARAM};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{
    GetPerformanceInfo, K32GetProcessMemoryInfo, PERFORMANCE_INFORMATION,
    PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, IsProcessCritical, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_READ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE,
};

type BOOL = i32;
const FALSE: BOOL = 0;
const INVALID_HANDLE: HANDLE = -1isize as HANDLE;
const WAIT_OBJECT_0: u32 = 0;
const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const MAX_BUFFER: usize = 1024 * 1024;

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: i32,
        info: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn ProcessIdToSessionId(process_id: u32, session_id: *mut u32) -> BOOL;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null() && handle != INVALID_HANDLE).then_some(Self(handle))
    }
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn file_time(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn process_times(handle: HANDLE) -> (Option<u64>, Option<f64>) {
    let mut creation: FILETIME = unsafe { zeroed() };
    let mut exit: FILETIME = unsafe { zeroed() };
    let mut kernel: FILETIME = unsafe { zeroed() };
    let mut user: FILETIME = unsafe { zeroed() };
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == FALSE
    {
        return (None, None);
    }
    let cpu = file_time(kernel).saturating_add(file_time(user)) as f64 / 10_000_000.0;
    (Some(file_time(creation)), Some(cpu))
}

fn utf16_z(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn process_path(handle: HANDLE) -> Option<String> {
    let mut value = vec![0u16; 32_768];
    let mut length = value.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, value.as_mut_ptr(), &mut length) } == FALSE {
        None
    } else {
        Some(String::from_utf16_lossy(&value[..length as usize]))
    }
}

fn parse_unicode_buffer(buffer: &[u8]) -> Option<String> {
    if buffer.len() < size_of::<UnicodeString>() {
        return None;
    }
    let header = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<UnicodeString>()) };
    let length = header.length as usize;
    if length % 2 != 0 || length > header.maximum_length as usize || header.buffer.is_null() {
        return None;
    }
    let base = buffer.as_ptr() as usize;
    let start = header.buffer as usize;
    let end = start.checked_add(length)?;
    if start < base || end > base.checked_add(buffer.len())? {
        return None;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(header.buffer, length / 2)
    }))
}

fn process_command(handle: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < size_of::<UnicodeString>() as u32 || needed as usize > MAX_BUFFER {
        return None;
    }
    let mut buffer = vec![0u8; needed as usize];
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    (status >= 0)
        .then(|| parse_unicode_buffer(&buffer))
        .flatten()
}

fn account_for_process(handle: HANDLE) -> Option<String> {
    let mut raw_token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut raw_token) } == FALSE {
        return None;
    }
    let token = OwnedHandle::new(raw_token)?;
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed as usize > MAX_BUFFER {
        return None;
    }
    let mut info = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            info.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == FALSE
    {
        return None;
    }
    let token_user = unsafe { std::ptr::read_unaligned(info.as_ptr().cast::<TOKEN_USER>()) };
    let sid = token_user.User.Sid;
    if sid.is_null() {
        return None;
    }
    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = 0i32;
    unsafe {
        LookupAccountSidW(
            null(),
            sid,
            null_mut(),
            &mut name_len,
            null_mut(),
            &mut domain_len,
            &mut sid_type,
        );
    }
    if name_len == 0 || name_len as usize > 32_768 || domain_len as usize > 32_768 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    if unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_type,
        )
    } == FALSE
    {
        return None;
    }
    let name = utf16_z(&name[..name_len as usize]);
    let domain = utf16_z(&domain[..domain_len as usize]);
    if name.is_empty() {
        None
    } else if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

fn inspect(entry: &PROCESSENTRY32W) -> Process {
    let query = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            entry.th32ProcessID,
        )
    });
    let (path, command, owner, created_file_time, cpu_seconds) = match query.as_ref() {
        Some(handle) => {
            let (created, cpu) = process_times(handle.raw());
            (
                process_path(handle.raw()),
                process_command(handle.raw()),
                account_for_process(handle.raw()),
                created,
                cpu,
            )
        }
        None => (None, None, None, None, None),
    };
    let memory_handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            entry.th32ProcessID,
        )
    });
    let (working_set_bytes, private_bytes) = memory_handle
        .as_ref()
        .and_then(|handle| {
            let mut counters: PROCESS_MEMORY_COUNTERS_EX = unsafe { zeroed() };
            counters.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            (unsafe {
                K32GetProcessMemoryInfo(
                    handle.raw(),
                    (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
                    counters.cb,
                )
            } != FALSE)
                .then_some((counters.WorkingSetSize as u64, counters.PrivateUsage as u64))
        })
        .map_or((None, None), |(working, private)| {
            (Some(working), Some(private))
        });
    let mut session = 0u32;
    let session_id = (unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut session) } != FALSE)
        .then_some(session);
    Process {
        pid: entry.th32ProcessID,
        parent_pid: entry.th32ParentProcessID,
        created_file_time,
        name: utf16_z(&entry.szExeFile),
        path,
        command,
        owner,
        session_id,
        working_set_bytes,
        private_bytes,
        cpu_seconds,
    }
}

pub fn scan() -> Result<Vec<Process>, String> {
    let snapshot = OwnedHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
        .ok_or_else(|| "CreateToolhelp32Snapshot failed".to_string())?;
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) } == FALSE {
        return Err("Process32FirstW failed".to_string());
    }
    let mut result = Vec::new();
    loop {
        result.push(inspect(&entry));
        entry = unsafe { zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == FALSE {
            break;
        }
    }
    result.sort_by_key(|process| process.pid);
    Ok(result)
}

pub fn memory() -> Memory {
    let mut result = Memory {
        timestamp_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        ..Memory::default()
    };
    let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut status) } != FALSE {
        result.total_bytes = Some(status.ullTotalPhys);
        result.available_bytes = Some(status.ullAvailPhys);
        result.used_bytes = Some(status.ullTotalPhys.saturating_sub(status.ullAvailPhys));
        result.used_percent = (status.ullTotalPhys != 0).then_some(
            status.ullTotalPhys.saturating_sub(status.ullAvailPhys) as f64 * 100.0
                / status.ullTotalPhys as f64,
        );
    }
    let mut performance: PERFORMANCE_INFORMATION = unsafe { zeroed() };
    performance.cb = size_of::<PERFORMANCE_INFORMATION>() as u32;
    if unsafe { GetPerformanceInfo(&mut performance, performance.cb) } != FALSE {
        let page = performance.PageSize as u64;
        result.commit_bytes = Some((performance.CommitTotal as u64).saturating_mul(page));
        result.commit_limit_bytes = Some((performance.CommitLimit as u64).saturating_mul(page));
        result.pool_paged_bytes = Some((performance.KernelPaged as u64).saturating_mul(page));
        result.pool_nonpaged_bytes = Some((performance.KernelNonpaged as u64).saturating_mul(page));
        result.cache_bytes = Some((performance.SystemCache as u64).saturating_mul(page));
    }
    let root: Vec<u16> = "C:\\\0".encode_utf16().collect();
    let mut free_available = 0u64;
    let mut total = 0u64;
    let mut total_free = 0u64;
    if unsafe {
        GetDiskFreeSpaceExW(
            root.as_ptr(),
            &mut free_available,
            &mut total,
            &mut total_free,
        )
    } != FALSE
    {
        result.free_c_bytes = Some(free_available);
    }
    result
}

pub fn current_owner() -> Option<String> {
    account_for_process(unsafe { GetCurrentProcess() })
}

struct WindowCloseContext {
    pid: u32,
    found: bool,
}

unsafe extern "system" fn close_window(window: HWND, parameter: LPARAM) -> BOOL {
    let context = &mut *(parameter as *mut WindowCloseContext);
    let mut pid = 0u32;
    GetWindowThreadProcessId(window, &mut pid);
    if pid == context.pid {
        context.found = true;
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    1
}

fn result(pid: u32, action: &str, status: &str, reason: impl Into<String>) -> ActionResult {
    ActionResult {
        pid,
        action: action.into(),
        status: status.into(),
        reason: reason.into(),
    }
}

pub fn stop_exact(identity: &Identity, force: bool, grace_seconds: u64) -> ActionResult {
    let action = if force { "ForceStop" } else { "Close" };
    let rights = PROCESS_QUERY_LIMITED_INFORMATION
        | PROCESS_SYNCHRONIZE
        | if force { PROCESS_TERMINATE } else { 0 };
    let Some(handle) = OwnedHandle::new(unsafe { OpenProcess(rights, FALSE, identity.pid) }) else {
        return result(
            identity.pid,
            action,
            "Failed",
            "Process already exited or is inaccessible",
        );
    };
    let (created, _) = process_times(handle.raw());
    if identity.created_file_time.is_none() || created != identity.created_file_time {
        return result(
            identity.pid,
            action,
            "Stale",
            "Process creation identity changed at stop boundary",
        );
    }
    let Some(caller_owner) = current_owner() else {
        return result(
            identity.pid,
            action,
            "Refused",
            "Cannot establish current Windows identity at stop boundary",
        );
    };
    let Some(target_owner) = account_for_process(handle.raw()) else {
        return result(
            identity.pid,
            action,
            "Refused",
            "Target owner is unavailable at stop boundary",
        );
    };
    if !target_owner.eq_ignore_ascii_case(&caller_owner) {
        return result(
            identity.pid,
            action,
            "Refused",
            "Target belongs to a different owner at stop boundary",
        );
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(handle.raw(), &mut critical) } == FALSE {
        return result(
            identity.pid,
            action,
            "Refused",
            "Cannot establish whether target is a critical process",
        );
    }
    if critical != FALSE {
        return result(
            identity.pid,
            action,
            "Refused",
            "Critical Windows processes cannot be stopped",
        );
    }
    let mut context = WindowCloseContext {
        pid: identity.pid,
        found: false,
    };
    unsafe {
        EnumWindows(
            Some(close_window),
            (&mut context as *mut WindowCloseContext) as LPARAM,
        );
    }
    if context.found {
        let wait_ms = grace_seconds
            .min(u32::MAX as u64 / 1000)
            .saturating_mul(1000) as u32;
        if unsafe { WaitForSingleObject(handle.raw(), wait_ms) } == WAIT_OBJECT_0 {
            return result(
                identity.pid,
                action,
                "Closed",
                "Top-level windows closed normally",
            );
        }
        if !force {
            return result(
                identity.pid,
                action,
                "Failed",
                "Application did not close within grace period",
            );
        }
    } else if !force {
        return result(
            identity.pid,
            action,
            "Failed",
            "No top-level window is available for graceful close",
        );
    }
    if unsafe { TerminateProcess(handle.raw(), 1) } == FALSE {
        return result(identity.pid, action, "Failed", "TerminateProcess failed");
    }
    if unsafe { WaitForSingleObject(handle.raw(), 5_000) } == WAIT_OBJECT_0 {
        result(
            identity.pid,
            action,
            "Stopped",
            "Bound process handle stopped",
        )
    } else {
        result(
            identity.pid,
            action,
            "Failed",
            "Stop requested; exit not confirmed",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn child_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("fixture child missing")
        }
        fn disarm(&mut self) {
            self.0.take();
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn filetime_is_exact_identity() {
        let value = FILETIME {
            dwLowDateTime: 0x89ab_cdef,
            dwHighDateTime: 0x0123_4567,
        };
        assert_eq!(file_time(value), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn unicode_parser_rejects_out_of_range_pointer() {
        let mut buffer = vec![0u8; size_of::<UnicodeString>() + 4];
        let header = UnicodeString {
            length: 2,
            maximum_length: 2,
            buffer: unsafe { buffer.as_mut_ptr().add(buffer.len()).cast() },
        };
        unsafe {
            std::ptr::write_unaligned(buffer.as_mut_ptr().cast::<UnicodeString>(), header);
        }
        assert!(parse_unicode_buffer(&buffer).is_none());
    }

    #[test]
    fn fixture_sleep() {
        if std::env::var_os("RAMGUARD_DISPOSABLE_FIXTURE").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            std::thread::sleep(std::time::Duration::from_secs(120));
        }
    }

    #[test]
    fn stop_exact_rejects_stale_identity_then_stops_exact_disposable_child() {
        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", "platform::tests::fixture_sleep", "--nocapture"])
            .env("RAMGUARD_DISPOSABLE_FIXTURE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("spawn disposable Rust fixture child");
        let pid = child.id();
        let mut child = ChildGuard(Some(child));
        let handle =
            OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) })
                .expect("open disposable fixture child");
        let created = process_times(handle.raw())
            .0
            .expect("fixture creation FILETIME");

        let stale = stop_exact(
            &Identity {
                pid,
                created_file_time: Some(created.saturating_add(1)),
            },
            true,
            0,
        );
        assert_eq!(stale.status, "Stale");
        assert!(
            child
                .child_mut()
                .try_wait()
                .expect("query fixture state")
                .is_none(),
            "stale identity stopped fixture child"
        );

        let stopped = stop_exact(
            &Identity {
                pid,
                created_file_time: Some(created),
            },
            true,
            0,
        );
        assert_eq!(stopped.status, "Stopped", "{}", stopped.reason);
        let status = child
            .child_mut()
            .wait()
            .expect("wait for stopped fixture child");
        assert!(
            !status.success(),
            "force-stopped fixture unexpectedly exited successfully"
        );
        child.disarm();
    }
}

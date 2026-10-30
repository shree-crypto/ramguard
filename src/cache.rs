// SPDX-License-Identifier: GPL-3.0-only
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_INFO_BY_HANDLE_CLASS,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

const MIN_AGE_HOURS: u64 = 24;
const FILE_DISPOSITION_INFO_CLASS: FILE_INFO_BY_HANDLE_CLASS = 4;
const WINDOWS_TICKS_PER_HOUR: u64 = 36_000_000_000;
const FILE_LIST_DIRECTORY_ACCESS: u32 = 0x0000_0001;
#[cfg(test)]
const GENERIC_READ_ACCESS: u32 = 0x8000_0000;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CacheRoot {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub min_age_hours: u64,
    pub eligible: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CachePreview {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub logical_bytes: u64,
    pub eligible_files: u64,
    pub skipped_files: u64,
    pub eligible: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CacheResult {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub deleted_files: u64,
    pub skipped_files: u64,
    pub deleted_logical_bytes: u64,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
struct Definition {
    id: &'static str,
    name: &'static str,
    path: PathBuf,
    build_root: bool,
}

#[derive(Clone, Debug)]
struct FileSnapshot {
    path: PathBuf,
    identity: FileIdentity,
    size: u64,
    creation: u64,
    last_write: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index: u64,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn roots() -> Vec<CacheRoot> {
    let inspection = crate::platform::scan();
    definitions()
        .into_iter()
        .map(|definition| fresh_root(&definition, inspection.as_ref()))
        .collect()
}

pub fn preview(selected: &[CacheRoot]) -> Vec<CachePreview> {
    let fresh = roots();
    selected
        .iter()
        .map(|requested| match validate_selection(requested, &fresh) {
            Ok(root) => preview_root(&root),
            Err(reason) => CachePreview {
                id: requested.id.clone(),
                name: requested.name.clone(),
                path: requested.path.clone(),
                logical_bytes: 0,
                eligible_files: 0,
                skipped_files: 0,
                eligible: false,
                reason,
            },
        })
        .collect()
}

pub fn clean(selected: &[CacheRoot]) -> Vec<CacheResult> {
    let fresh = roots();
    let validated: Vec<Result<CacheRoot, String>> = selected
        .iter()
        .map(|requested| validate_selection(requested, &fresh))
        .collect();

    // Cleaning is all-or-nothing with respect to process visibility. A single
    // inspection failure means no selected cache file is touched.
    if let Err(error) = crate::platform::scan() {
        return inspection_failure_results(selected, &error);
    }

    validated
        .into_iter()
        .zip(selected)
        .map(|(validated, requested)| match validated {
            Ok(root) => clean_root(&root),
            Err(reason) => failed_result(requested, reason),
        })
        .collect()
}

fn inspection_failure_results(selected: &[CacheRoot], error: &str) -> Vec<CacheResult> {
    selected
        .iter()
        .map(|root| {
            failed_result(
                root,
                format!("Process inspection failed; no cache files were deleted: {error}"),
            )
        })
        .collect()
}

fn definitions() -> Vec<Definition> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_default();
    let catalog = vec![
        Definition {
            id: "userLocalTemp",
            name: "User local temporary files",
            path: local.join("Temp"),
            build_root: false,
        },
        Definition {
            id: "npmCache",
            name: "npm cache",
            path: local.join("npm-cache"),
            build_root: false,
        },
        Definition {
            id: "pipCache",
            name: "pip cache",
            path: local.join("pip").join("Cache"),
            build_root: false,
        },
    ];
    #[cfg(feature = "m5-tools")]
    let catalog = {
        let mut catalog = catalog;
        catalog.extend([
            Definition {
                id: "m5PlatformIoCache",
                name: "M5RobotTools PlatformIO cache",
                path: PathBuf::from(r"X:\M5RobotTools\platformio\.cache"),
                build_root: true,
            },
            Definition {
                id: "m5PublishArduinoBuild",
                name: "M5RobotTools publish Arduino last build",
                path: PathBuf::from(r"X:\M5RobotTools\publish-runtime\arduino\build"),
                build_root: true,
            },
            Definition {
                id: "m5RobotArduinoBuild",
                name: "M5RobotTools robot Arduino last build",
                path: PathBuf::from(r"X:\M5RobotTools\robot-runtime\arduino\build"),
                build_root: true,
            },
        ]);
        catalog
    };
    catalog
}

fn fresh_root(
    definition: &Definition,
    inspection: Result<&Vec<crate::model::Process>, &String>,
) -> CacheRoot {
    let (eligible, reason) = match validate_root_path(&definition.path) {
        Err(reason) => (false, reason),
        Ok(()) if definition.build_root => match inspection {
            Err(_) => (
                false,
                "Cannot inspect active compiler or flasher processes".to_string(),
            ),
            Ok(processes) if build_activity(processes) != BuildActivity::Idle => {
                let reason = if build_activity(processes) == BuildActivity::Active {
                    "Compiler or flasher process is active"
                } else {
                    "Compiler or flasher activity cannot be proven absent"
                };
                (false, reason.to_string())
            }
            Ok(_) => (true, "Eligible".to_string()),
        },
        Ok(()) => (true, "Eligible".to_string()),
    };
    CacheRoot {
        id: definition.id.to_string(),
        name: definition.name.to_string(),
        path: normalize_lexical(&definition.path),
        min_age_hours: MIN_AGE_HOURS,
        eligible,
        reason,
    }
}

fn validate_selection(requested: &CacheRoot, fresh: &[CacheRoot]) -> Result<CacheRoot, String> {
    let definition = definitions()
        .into_iter()
        .find(|item| item.id == requested.id)
        .ok_or_else(|| {
            "Roots may only select exact entries from the fixed cache catalog".to_string()
        })?;
    let expected_path = normalize_lexical(&definition.path);
    if requested.name != definition.name
        || requested.min_age_hours != MIN_AGE_HOURS
        || !path_eq(&normalize_lexical(&requested.path), &expected_path)
    {
        return Err("Roots may only select exact entries from the fixed cache catalog".to_string());
    }
    fresh
        .iter()
        .find(|root| root.id == requested.id)
        .cloned()
        .ok_or_else(|| "Cache root disappeared from the fixed catalog".to_string())
}

fn preview_root(root: &CacheRoot) -> CachePreview {
    let mut result = CachePreview {
        id: root.id.clone(),
        name: root.name.clone(),
        path: root.path.clone(),
        logical_bytes: 0,
        eligible_files: 0,
        skipped_files: 0,
        eligible: root.eligible,
        reason: root.reason.clone(),
    };
    if !root.eligible {
        return result;
    }
    let cutoff = cutoff_ticks(root.min_age_hours);
    walk_files(&root.path, |path| match snapshot(path) {
        Ok(file) if file.last_write <= cutoff => {
            result.eligible_files = result.eligible_files.saturating_add(1);
            result.logical_bytes = result.logical_bytes.saturating_add(file.size);
        }
        _ => result.skipped_files = result.skipped_files.saturating_add(1),
    });
    result
}

fn clean_root(root: &CacheRoot) -> CacheResult {
    let mut result = CacheResult {
        id: root.id.clone(),
        name: root.name.clone(),
        path: root.path.clone(),
        deleted_files: 0,
        skipped_files: 0,
        deleted_logical_bytes: 0,
        errors: Vec::new(),
    };
    if !root.eligible {
        result
            .errors
            .push(format!("{}: {}", root.path.display(), root.reason));
        return result;
    }

    let root_processes = match crate::platform::scan() {
        Ok(value) => value,
        Err(error) => {
            result.errors.push(format!(
                "Process inspection failed; this cache root was not cleaned: {error}"
            ));
            return result;
        }
    };

    let definition = match definitions().into_iter().find(|item| item.id == root.id) {
        Some(value) => value,
        None => {
            result
                .errors
                .push("Cache root is not in the fixed catalog".to_string());
            return result;
        }
    };
    let cutoff = cutoff_ticks(root.min_age_hours);
    if definition.build_root && build_activity(&root_processes) != BuildActivity::Idle {
        result.errors.push(format!(
            "{}: compiler or flasher activity could not be proven absent",
            root.path.display()
        ));
        return result;
    }
    let mut candidates = Vec::new();
    walk_files(&root.path, |path| candidates.push(path.to_path_buf()));

    let candidate_count = candidates.len() as u64;
    for (index, path) in candidates.into_iter().enumerate() {
        let before = match snapshot(&path) {
            Ok(value) if value.last_write <= cutoff => value,
            _ => {
                result.skipped_files += 1;
                continue;
            }
        };

        let processes = match crate::platform::scan() {
            Ok(value) => value,
            Err(error) => {
                result.skipped_files += candidate_count.saturating_sub(index as u64);
                result.errors.push(format!(
                    "Process inspection failed; remaining cache files were not deleted: {error}"
                ));
                break;
            }
        };
        if definition.build_root && build_activity(&processes) != BuildActivity::Idle {
            result.skipped_files += 1;
            continue;
        }
        if command_references(&processes, &before.path) {
            result.skipped_files += 1;
            continue;
        }

        match try_delete(&root.path, &before) {
            Ok(bytes) => {
                result.deleted_files += 1;
                result.deleted_logical_bytes = result.deleted_logical_bytes.saturating_add(bytes);
            }
            Err(error) => {
                result.skipped_files += 1;
                result
                    .errors
                    .push(format!("{}: {error}", before.path.display()));
            }
        }
    }
    result
}

fn failed_result(root: &CacheRoot, error: String) -> CacheResult {
    CacheResult {
        id: root.id.clone(),
        name: root.name.clone(),
        path: root.path.clone(),
        deleted_files: 0,
        skipped_files: 0,
        deleted_logical_bytes: 0,
        errors: vec![error],
    }
}

fn walk_files(root: &Path, mut visit: impl FnMut(&Path)) {
    let root = normalize_lexical(root);
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        if !is_beneath(&directory, &root, true) {
            continue;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(value) => value,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = normalize_lexical(&entry.path());
            if !is_beneath(&path, &root, false) {
                continue;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                visit(&path);
            }
        }
    }
}

fn validate_root_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err("Cache root is not an absolute path".to_string());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| "Path does not exist".to_string())?;
    if !metadata.is_dir() {
        return Err("Path is not a directory".to_string());
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "Root ancestry cannot be inspected".to_string())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("Root or an ancestor is a reparse point".to_string());
        }
    }
    Ok(())
}

fn snapshot(path: &Path) -> io::Result<FileSnapshot> {
    let handle = open_handle(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        false,
    )?;
    let info = handle_info(&handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "File is a reparse point",
        ));
    }
    verify_final_path(&handle, path)?;
    Ok(FileSnapshot {
        path: normalize_lexical(path),
        identity: identity(&info),
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        creation: filetime(
            info.ftCreationTime.dwHighDateTime,
            info.ftCreationTime.dwLowDateTime,
        ),
        last_write: filetime(
            info.ftLastWriteTime.dwHighDateTime,
            info.ftLastWriteTime.dwLowDateTime,
        ),
    })
}

fn try_delete(root: &Path, expected: &FileSnapshot) -> io::Result<u64> {
    if !is_beneath(&expected.path, root, false) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "File is outside the protected root",
        ));
    }
    let mut held = Vec::new();
    for directory in directory_chain(root, &expected.path)? {
        // FILE_LIST_DIRECTORY is intentional: an attribute-only directory
        // handle does not reliably enforce the missing write/delete shares.
        let handle = open_handle(
            &directory,
            FILE_LIST_DIRECTORY_ACCESS | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            true,
        )?;
        let info = handle_info(&handle)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Protected directory is a reparse point",
            ));
        }
        verify_final_path(&handle, &directory)?;
        held.push(handle);
    }

    let file = open_handle(
        &expected.path,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        false,
    )?;
    let info = handle_info(&file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "File is a reparse point",
        ));
    }
    verify_final_path(&file, &expected.path)?;
    let current = FileSnapshot {
        path: expected.path.clone(),
        identity: identity(&info),
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        creation: filetime(
            info.ftCreationTime.dwHighDateTime,
            info.ftCreationTime.dwLowDateTime,
        ),
        last_write: filetime(
            info.ftLastWriteTime.dwHighDateTime,
            info.ftLastWriteTime.dwLowDateTime,
        ),
    };
    if current.identity != expected.identity
        || current.size != expected.size
        || current.creation != expected.creation
        || current.last_write != expected.last_write
    {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "File changed after eligibility was established",
        ));
    }

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.0,
            FILE_DISPOSITION_INFO_CLASS,
            &disposition as *const _ as *const _,
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(file);
    drop(held);
    Ok(expected.size)
}

fn open_handle(path: &Path, access: u32, share: u32, directory: bool) -> io::Result<OwnedHandle> {
    let wide = wide(path.as_os_str());
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle(handle))
    }
}

fn handle_info(handle: &OwnedHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

fn verify_final_path(handle: &OwnedHandle, expected: &Path) -> io::Result<()> {
    let mut buffer = vec![0u16; 32_768];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle.0, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::last_os_error());
    }
    let raw = String::from_utf16_lossy(&buffer[..length as usize]);
    let final_path = if let Some(value) = raw.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{value}"))
    } else if let Some(value) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(value)
    } else {
        PathBuf::from(raw)
    };
    if path_eq(
        &normalize_lexical(&final_path),
        &normalize_lexical(expected),
    ) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Handle resolved to a different path",
        ))
    }
}

fn directory_chain(root: &Path, file: &Path) -> io::Result<Vec<PathBuf>> {
    let root = normalize_lexical(root);
    let parent = normalize_lexical(
        file.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "File has no parent"))?,
    );
    if !is_beneath(&parent, &root, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "File is outside the protected root",
        ));
    }
    let mut ancestors: Vec<PathBuf> = root.ancestors().map(Path::to_path_buf).collect();
    ancestors.reverse();
    let relative = parent.strip_prefix(&root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "File is outside the protected root",
        )
    })?;
    let mut current = root;
    for component in relative.components() {
        current.push(component.as_os_str());
        ancestors.push(current.clone());
    }
    Ok(ancestors)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BuildActivity {
    Idle,
    Active,
    Unknown,
}

fn build_activity(processes: &[crate::model::Process]) -> BuildActivity {
    let mut unknown = false;
    for process in processes {
        let name = process.name.to_ascii_lowercase();
        let command = process
            .command
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let text = format!("{name} {command}");
        if is_build_command(&text) {
            return BuildActivity::Active;
        }
        if process.command.is_none()
            && matches!(
                name.as_str(),
                "python" | "python.exe" | "python3" | "python3.exe"
            )
        {
            unknown = true;
        }
    }
    if unknown {
        BuildActivity::Unknown
    } else {
        BuildActivity::Idle
    }
}

fn is_build_command(text: &str) -> bool {
    [
        "arduino-cli",
        "platformio",
        "pio.exe",
        "esptool",
        "avrdude",
        "bossac",
        "openocd",
        "xtensa-",
        "riscv",
        "gcc",
        "g++",
        "clang",
        "cc1",
        "cc1plus",
        "dfu-util",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn command_references(processes: &[crate::model::Process], path: &Path) -> bool {
    let needle = normalize_lexical(path)
        .to_string_lossy()
        .to_ascii_lowercase();
    processes
        .iter()
        .filter_map(|process| process.command.as_deref())
        .any(|command| command.to_ascii_lowercase().contains(&needle))
}

fn cutoff_ticks(hours: u64) -> u64 {
    crate::model::now_file_time().saturating_sub(hours.saturating_mul(WINDOWS_TICKS_PER_HOUR))
}

fn filetime(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | low as u64
}

fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> FileIdentity {
    FileIdentity {
        volume: info.dwVolumeSerialNumber,
        index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn path_eq(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn is_beneath(path: &Path, parent: &Path, allow_equal: bool) -> bool {
    let path = normalize_lexical(path);
    let parent = normalize_lexical(parent);
    if path_eq(&path, &parent) {
        return allow_equal;
    }
    let path_text = path.to_string_lossy();
    let mut prefix = parent.to_string_lossy().into_owned();
    if !prefix.ends_with(['\\', '/']) {
        prefix.push('\\');
    }
    path_text.len() > prefix.len() && path_text[..prefix.len()].eq_ignore_ascii_case(&prefix)
}

#[cfg(test)]
fn fixture_root(path: &Path, id: &str) -> io::Result<CacheRoot> {
    let temp = normalize_lexical(&std::env::temp_dir());
    let path = normalize_lexical(path);
    if !is_beneath(&path, &temp, false) || !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Fixture must be a unique directory beneath the system temporary directory",
        ));
    }
    // Reject shared/common temp locations; the fixture must have a unique leaf.
    let leaf = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    if leaf.len() < 12 || !leaf.contains(id) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Fixture directory is not uniquely scoped",
        ));
    }
    validate_root_path(&path)
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
    Ok(CacheRoot {
        id: id.to_string(),
        name: "test fixture".to_string(),
        path,
        min_age_hours: 0,
        eligible: true,
        reason: "Eligible test fixture".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_is_generic_and_m5_profile_is_explicit() {
        let catalog = definitions();
        assert_eq!(
            catalog.len(),
            if cfg!(feature = "m5-tools") { 6 } else { 3 }
        );
        assert_eq!(
            catalog.iter().any(|root| root.id.starts_with("m5")),
            cfg!(feature = "m5-tools")
        );
    }
    use std::fs::{File, FileTimes};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ramguard-{label}-{}-{}-{serial}",
                std::process::id(),
                crate::model::now_file_time(),
            ));
            fs::create_dir(&path).expect("create isolated cache fixture");
            fixture_root(&path, label).expect("fixture containment");
            Self(path)
        }

        fn root(&self, age: u64) -> CacheRoot {
            CacheRoot {
                id: "fixture".to_string(),
                name: "fixture".to_string(),
                path: self.0.clone(),
                min_age_hours: age,
                eligible: true,
                reason: "Eligible test fixture".to_string(),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn old_file(path: &Path) {
        fs::write(path, b"old").unwrap();
        let old = SystemTime::now() - Duration::from_secs(25 * 60 * 60);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(old))
            .unwrap();
    }

    #[test]
    fn preview_separates_old_and_young_files() {
        let fixture = Fixture::new("age");
        old_file(&fixture.0.join("old.bin"));
        fs::write(fixture.0.join("young.bin"), b"young").unwrap();
        let preview = preview_root(&fixture.root(24));
        assert_eq!(preview.eligible_files, 1);
        assert_eq!(preview.skipped_files, 1);
        assert_eq!(preview.logical_bytes, 3);
    }

    #[test]
    fn locked_file_is_not_deleted() {
        let fixture = Fixture::new("lock");
        let path = fixture.0.join("locked.bin");
        old_file(&path);
        let before = snapshot(&path).unwrap();
        let lock = open_handle(&path, GENERIC_READ_ACCESS, FILE_SHARE_READ, false).unwrap();
        assert!(try_delete(&fixture.0, &before).is_err());
        assert!(path.exists());
        drop(lock);
    }

    #[test]
    fn unlocked_file_is_deleted() {
        let fixture = Fixture::new("unlocked");
        let path = fixture.0.join("unlocked.bin");
        old_file(&path);
        let before = snapshot(&path).unwrap();
        assert_eq!(try_delete(&fixture.0, &before).unwrap(), 3);
        assert!(!path.exists());
    }

    #[test]
    fn held_directory_cannot_be_renamed() {
        let fixture = Fixture::new("dirhold");
        let directory = fixture.0.join("held");
        let renamed = fixture.0.join("renamed");
        fs::create_dir(&directory).unwrap();
        let hold = open_handle(
            &directory,
            FILE_LIST_DIRECTORY_ACCESS | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            true,
        )
        .unwrap();
        assert!(fs::rename(&directory, &renamed).is_err());
        assert!(directory.exists());
        drop(hold);
    }

    #[test]
    fn changed_identity_is_not_deleted() {
        let fixture = Fixture::new("identity");
        let path = fixture.0.join("changed.bin");
        old_file(&path);
        let before = snapshot(&path).unwrap();
        fs::remove_file(&path).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&path, b"new identity").unwrap();
        assert!(try_delete(&fixture.0, &before).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"new identity");
    }

    #[test]
    fn read_only_attribute_is_not_changed_to_force_deletion() {
        let fixture = Fixture::new("readonly");
        let path = fixture.0.join("readonly.bin");
        old_file(&path);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let before = snapshot(&path).unwrap();
        assert!(try_delete(&fixture.0, &before).is_err());
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
    }

    #[test]
    fn directory_junction_or_symlink_is_not_traversed() {
        let fixture = Fixture::new("junction");
        let target = fixture.0.join("target");
        fs::create_dir(&target).unwrap();
        old_file(&target.join("outside.bin"));
        let linked = fixture.0.join("linked");
        if std::os::windows::fs::symlink_dir(&target, &linked).is_err() {
            let command = format!(
                "mklink /J \"{}\" \"{}\"",
                linked.display(),
                target.display(),
            );
            let status = std::process::Command::new("cmd.exe")
                .args(["/d", "/s", "/c", &command])
                .status()
                .expect("run mklink fallback for contained test junction");
            assert!(status.success(), "could not create contained test junction");
        }
        let mut seen = Vec::new();
        walk_files(&linked.parent().unwrap(), |path| {
            seen.push(path.to_path_buf())
        });
        assert!(!seen.iter().any(|path| path.starts_with(&linked)));
    }

    #[test]
    fn production_path_override_is_rejected() {
        let definition = definitions().into_iter().next().unwrap();
        let fresh = vec![CacheRoot {
            id: definition.id.to_string(),
            name: definition.name.to_string(),
            path: definition.path.clone(),
            min_age_hours: MIN_AGE_HOURS,
            eligible: true,
            reason: "Eligible".to_string(),
        }];
        let fixture = Fixture::new("override");
        let requested = CacheRoot {
            path: fixture.0.clone(),
            ..fresh[0].clone()
        };
        assert!(validate_selection(&requested, &fresh).is_err());
    }

    #[test]
    fn failed_process_inspection_produces_only_failures() {
        let fixture = Fixture::new("inspection");
        let path = fixture.0.join("untouched.bin");
        old_file(&path);
        let results = inspection_failure_results(&[fixture.root(24)], "mock failure");
        assert_eq!(results[0].deleted_files, 0);
        assert!(results[0].errors[0].contains("mock failure"));
        assert!(path.exists());
    }
}

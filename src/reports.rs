// SPDX-License-Identifier: GPL-3.0-only
use crate::model::{Group, Identity, RestartedFamily};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE: AtomicU64 = AtomicU64::new(0);

const REDACTED: &str = "[REDACTED]";
const RETAINED_REPORTS: usize = 30;

/// Save a sanitized report atomically and retain only the 30 newest RamGuard reports.
pub fn save(report: &Value, directory: Option<&Path>) -> Result<PathBuf, String> {
    let directory = match directory {
        Some(path) => absolute_path(path)?,
        None => {
            let local = std::env::var_os("LOCALAPPDATA")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "The local application-data directory is unavailable".to_string())?;
            absolute_path(&PathBuf::from(local).join("RamGuard").join("reports"))?
        }
    };

    reject_reparse_ancestors(&directory)?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Could not create the report directory".to_string())?;
    reject_reparse_ancestors(&directory)?;

    let mut sanitized = report.clone();
    redact(&mut sanitized);
    let bytes = serde_json::to_vec_pretty(&sanitized)
        .map_err(|_| "Could not serialize the report".to_string())?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let pid = std::process::id();
    let seed = now.as_nanos() as u64 ^ NONCE.fetch_add(1, Ordering::Relaxed);

    for attempt in 0..128u64 {
        let nonce = seed.wrapping_add(attempt);
        let final_path = directory.join(format!(
            "report-native-{:020}-{pid:010}-{nonce:032x}.json",
            now.as_secs()
        ));
        if final_path.exists() {
            continue;
        }
        let temporary = directory.join(format!(".ramguard-{pid}-{nonce}.tmp"));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("Could not create the temporary report".to_string()),
        };

        let write_result = file.write_all(&bytes).and_then(|_| file.sync_all());
        drop(file);
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err("Could not write the report".to_string());
        }
        if fs::rename(&temporary, &final_path).is_err() {
            let _ = fs::remove_file(&temporary);
            continue;
        }

        retain_newest(&directory);
        return Ok(final_path);
    }

    Err("Could not allocate a unique report filename".to_string())
}

/// Find new process identities in families that RamGuard actually closed.
pub fn restarted(closed: &[Group], baseline: &[Group], after: &[Group]) -> Vec<RestartedFamily> {
    let mut family_order = Vec::new();
    let mut targeted = HashSet::new();
    for group in closed {
        if targeted.insert(group.family.clone()) {
            family_order.push(group.family.clone());
        }
    }

    let mut before: HashMap<&str, HashSet<Identity>> = HashMap::new();
    for group in baseline {
        before
            .entry(group.family.as_str())
            .or_default()
            .extend(group.identities.iter().cloned());
    }
    let mut current: HashMap<&str, Vec<Identity>> = HashMap::new();
    for group in after {
        current
            .entry(group.family.as_str())
            .or_default()
            .extend(group.identities.iter().cloned());
    }

    let mut result = Vec::new();
    for family in family_order {
        let old = before.get(family.as_str());
        let mut seen = HashSet::new();
        let new_identities: Vec<Identity> = current
            .get(family.as_str())
            .into_iter()
            .flatten()
            .filter(|identity| old.map_or(true, |identities| !identities.contains(*identity)))
            .filter(|identity| seen.insert((*identity).clone()))
            .cloned()
            .collect();
        if !new_identities.is_empty() {
            result.push(RestartedFamily {
                family,
                new_identities,
            });
        }
    }
    result
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|_| "Could not resolve the report directory".to_string())
    }
}

fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let normalized: String = key
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                if is_sensitive_key(&normalized) {
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "command"
            | "commandline"
            | "fullcommandline"
            | "token"
            | "tokens"
            | "apikeys"
            | "authorization"
            | "password"
            | "secret"
            | "credentials"
            | "cookie"
            | "conversationcontent"
            | "messagescontent"
    )
}

fn retain_newest(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut reports = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_owned_report_name(name) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH);
        reports.push((modified, name.to_owned(), entry.path()));
    }
    reports.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, _, path) in reports.into_iter().skip(RETAINED_REPORTS) {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_file() && !is_reparse(&metadata) {
            let _ = fs::remove_file(path);
        }
    }
}

fn is_owned_report_name(name: &str) -> bool {
    if let Some(stem) = name
        .strip_prefix("report-native-")
        .and_then(|value| value.strip_suffix(".json"))
    {
        let parts: Vec<&str> = stem.split('-').collect();
        return parts.len() == 3
            && digits(parts[0], 20)
            && digits(parts[1], 10)
            && hex_digits(parts[2], 32);
    }

    let Some(stem) = name
        .strip_prefix("report-")
        .and_then(|value| value.strip_suffix(".json"))
    else {
        return false;
    };
    let parts: Vec<&str> = stem.split('-').collect();
    parts.len() == 4
        && digits(parts[0], 8)
        && digits(parts[1], 6)
        && digits(parts[2], 3)
        && hex_digits(parts[3], 32)
}

fn digits(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn hex_digits(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn reject_reparse_ancestors(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_reparse(&metadata) => {
                return Err(
                    "The report directory cannot traverse a link or reparse point".to_string(),
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Could not inspect the report directory".to_string()),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Classification;

    fn group(
        family: &str,
        identities: &[(u32, Option<u64>)],
        classification: Classification,
    ) -> Group {
        Group {
            id: family.to_string(),
            name: family.to_string(),
            family: family.to_string(),
            identities: identities
                .iter()
                .map(|(pid, time)| Identity {
                    pid: *pid,
                    created_file_time: *time,
                })
                .collect(),
            working_set_bytes: 0,
            classification,
            reason: String::new(),
        }
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ramguard-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    fn cleanup(path: &Path) {
        assert!(path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("ramguard-")));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn save_redacts_recursively_and_keeps_operation() {
        let directory = temporary_directory("redaction");
        let value = serde_json::json!({
            "Operation": "Close",
            "CommandLine": "private command",
            "nested": [{"api_keys": ["private"], "MessagesContent": "private"}]
        });
        let path = save(&value, Some(&directory)).unwrap();
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("report-native-"));
        assert!(is_owned_report_name(&filename));
        let written: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(written["Operation"], "Close");
        assert_eq!(written["CommandLine"], REDACTED);
        assert_eq!(written["nested"][0]["api_keys"], REDACTED);
        assert_eq!(written["nested"][0]["MessagesContent"], REDACTED);
        assert!(!fs::read_dir(&directory)
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".tmp")));
        cleanup(&directory);
    }

    #[test]
    fn retention_counts_legacy_reports_but_preserves_numeric_decoys() {
        let directory = temporary_directory("retention");
        for number in 0..35 {
            fs::write(
                directory.join(format!(
                    "report-20261030-211500-{number:03}-{number:032x}.json"
                )),
                b"{}",
            )
            .unwrap();
        }
        fs::write(directory.join("report-2026-10-30.json"), b"keep").unwrap();
        fs::write(directory.join("report-not-ours.json"), b"keep").unwrap();
        fs::write(directory.join("notes.txt"), b"keep").unwrap();
        retain_newest(&directory);
        assert_eq!(
            fs::read_dir(&directory)
                .unwrap()
                .flatten()
                .filter(|entry| is_owned_report_name(&entry.file_name().to_string_lossy()))
                .count(),
            30
        );
        assert!(directory.join("report-2026-10-30.json").exists());
        assert!(directory.join("report-not-ours.json").exists());
        assert!(directory.join("notes.txt").exists());
        cleanup(&directory);
    }

    #[test]
    fn retention_does_not_follow_or_remove_symlinks() {
        let directory = temporary_directory("symlink-retention");
        let target = directory.join("target.json");
        let link = directory.join(
            "report-native-00000000001767108900-0000000001-00000000000000000000000000000001.json",
        );
        fs::write(&target, b"keep").unwrap();
        if create_file_symlink(&target, &link).is_err() {
            cleanup(&directory);
            return;
        }
        for number in 0..31 {
            fs::write(
                directory.join(format!(
                    "report-native-00000000001767108900-0000000002-{number:032x}.json"
                )),
                b"{}",
            )
            .unwrap();
        }
        retain_newest(&directory);
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        cleanup(&directory);
    }

    #[test]
    fn restarted_deduplicates_families_and_uses_full_identity() {
        let closed = vec![
            group("browser", &[(7, Some(10))], Classification::Automatic),
            group("browser", &[(8, Some(20))], Classification::Manual),
        ];
        let baseline = vec![group(
            "browser",
            &[(7, Some(10)), (99, Some(5))],
            Classification::Manual,
        )];
        let after = vec![
            group(
                "browser",
                &[(99, Some(5)), (7, Some(11))],
                Classification::Manual,
            ),
            group("browser", &[(7, Some(11))], Classification::Automatic),
            group("other", &[(1, Some(1))], Classification::Automatic),
        ];
        let result = restarted(&closed, &baseline, &after);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].family, "browser");
        assert_eq!(
            result[0].new_identities,
            vec![Identity {
                pid: 7,
                created_file_time: Some(11)
            }]
        );
    }

    #[test]
    fn existing_siblings_are_not_restarts_and_unclosed_families_are_ignored() {
        let closed = vec![group("editor", &[(1, Some(1))], Classification::Manual)];
        let baseline = vec![group("editor", &[(2, Some(2))], Classification::Manual)];
        let after = vec![
            group("editor", &[(2, Some(2))], Classification::Manual),
            group("browser", &[(4, Some(4))], Classification::Automatic),
        ];
        assert!(restarted(&closed, &baseline, &after).is_empty());
    }

    #[cfg(windows)]
    fn create_file_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(original, link)
    }

    #[cfg(unix)]
    fn create_file_symlink(original: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(original, link)
    }
}

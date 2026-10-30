// SPDX-License-Identifier: GPL-3.0-only
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Process {
    pub pid: u32,
    pub parent_pid: u32,
    pub created_file_time: Option<u64>,
    pub name: String,
    pub path: Option<String>,
    #[serde(skip_serializing)]
    pub command: Option<String>,
    pub owner: Option<String>,
    pub session_id: Option<u32>,
    pub working_set_bytes: Option<u64>,
    pub private_bytes: Option<u64>,
    pub cpu_seconds: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Memory {
    pub timestamp_unix_seconds: u64,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub used_percent: Option<f64>,
    pub commit_bytes: Option<u64>,
    pub commit_limit_bytes: Option<u64>,
    pub pool_paged_bytes: Option<u64>,
    pub pool_nonpaged_bytes: Option<u64>,
    pub cache_bytes: Option<u64>,
    pub compression_bytes: Option<u64>,
    pub free_c_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Identity {
    pub pid: u32,
    pub created_file_time: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Protected,
    Automatic,
    Manual,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    pub family: String,
    pub identities: Vec<Identity>,
    pub working_set_bytes: u64,
    pub classification: Classification,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionResult {
    pub pid: u32,
    pub action: String,
    pub status: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestartedFamily {
    pub family: String,
    pub new_identities: Vec<Identity>,
}

pub fn now_file_time() -> u64 {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    116_444_736_000_000_000u64
        .saturating_add(elapsed.as_secs().saturating_mul(10_000_000))
        .saturating_add(elapsed.subsec_nanos() as u64 / 100)
}

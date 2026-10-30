// SPDX-License-Identifier: GPL-3.0-only
use crate::model::{ActionResult, Classification, Group, Identity, Process};
use crate::platform;
use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::Duration;

const FIVE_MINUTES_FILETIME: u64 = 5 * 60 * 10_000_000;

fn lower(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn is_shared_boundary(process: &Process) -> bool {
    let name = lower(&process.name);
    let command = lower(process.command.as_deref().unwrap_or(""));
    matches!(
        name.trim_end_matches(".exe"),
        "explorer"
            | "services"
            | "svchost"
            | "wininit"
            | "sihost"
            | "startmenuexperiencehost"
            | "shellexperiencehost"
            | "windowsterminal"
    ) || name.contains("codex")
        || name.contains("chatgpt")
        || command.contains("codex-app-server")
        || (command.contains("chatgpt")
            && (command.contains("backend") || command.contains("service")))
}

fn known_helper(process: &Process) -> bool {
    let name = lower(&process.name);
    let base = name.trim_end_matches(".exe");
    if matches!(
        base,
        "chromedriver" | "geckodriver" | "iedriverserver" | "playwright" | "cadgen"
    ) {
        return true;
    }
    let command = lower(process.command.as_deref().unwrap_or(""));
    let runtime = matches!(base, "node" | "python" | "pythonw" | "java");
    let browser_marker = [
        "ms-playwright",
        "playwright/",
        "playwright\\",
        "puppeteer",
        "selenium/",
        "selenium\\",
        "webdriver",
        "require-browser-access",
        "node_repl",
    ]
    .iter()
    .any(|marker| command.contains(marker));
    (runtime && browser_marker)
        || command.split_whitespace().any(|part| {
            let part = part.trim_matches('"').to_ascii_lowercase();
            part == "cadgen" || part.ends_with("\\cadgen.cmd") || part.ends_with("\\cadgen.exe")
        })
}

fn intrinsic_protection(process: &Process, current_owner: Option<&str>) -> Option<&'static str> {
    let Some(current_owner) = current_owner.filter(|value| !value.trim().is_empty()) else {
        return Some("Cannot establish current Windows identity");
    };
    if process.pid <= 4 {
        return Some("Windows kernel process");
    }
    if process.session_id == Some(0) {
        return Some("Windows service session");
    }
    let Some(owner) = process
        .owner
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Some("Owner unavailable; permission-safe protection");
    };
    let name = lower(&process.name);
    let base = name.trim_end_matches(".exe");
    let command = lower(process.command.as_deref().unwrap_or(""));
    if matches!(
        base,
        "system"
            | "registry"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "winlogon"
            | "fontdrvhost"
            | "dwm"
            | "sihost"
            | "securityhealthservice"
            | "securityhealthsystray"
            | "msmpeng"
            | "nissrv"
            | "sense"
            | "svchost"
    ) {
        return Some("Windows system or security process");
    }
    let security_prefix = [
        "mc-",
        "mf",
        "masvc",
        "csfalcon",
        "sentinel",
        "cylance",
        "cb",
        "carbonblack",
        "sophos",
        "symantec",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix));
    if security_prefix
        || ["firewall", "antivirus", "endpoint", "security", "defender"]
            .iter()
            .any(|part| name.contains(part))
    {
        return Some("Security vendor process");
    }
    if matches!(
        base,
        "explorer" | "startmenuexperiencehost" | "shellexperiencehost" | "windowsterminal"
    ) {
        return Some("Shared Windows shell");
    }
    if name.contains("codex")
        || name.contains("chatgpt")
        || command.contains("codex-app-server")
        || (command.contains("chatgpt")
            && (command.contains("backend") || command.contains("service")))
    {
        return Some("Shared Codex or ChatGPT backend");
    }
    if command.contains("run_companion.py") {
        return Some("M5 companion process");
    }
    if !owner.eq_ignore_ascii_case(current_owner) {
        return Some("Process belongs to a different owner");
    }
    None
}

fn add_ancestors(set: &mut HashSet<u32>, start: u32, by_pid: &HashMap<u32, &Process>) {
    let mut cursor = start;
    let mut seen = HashSet::new();
    while cursor > 0 && seen.insert(cursor) {
        let Some(process) = by_pid.get(&cursor) else {
            break;
        };
        set.insert(cursor);
        cursor = process.parent_pid;
    }
}

pub fn classify(
    processes: &[Process],
    current_pid: u32,
    current_owner: Option<&str>,
    thread_markers: &[String],
    now_file_time: u64,
) -> Vec<Group> {
    let items: Vec<&Process> = processes.iter().filter(|process| process.pid > 0).collect();
    let by_pid: HashMap<u32, &Process> = items
        .iter()
        .map(|process| (process.pid, *process))
        .collect();
    let mut protected = HashSet::new();
    add_ancestors(&mut protected, current_pid, &by_pid);
    for marker in thread_markers
        .iter()
        .filter(|marker| !marker.trim().is_empty())
    {
        for process in &items {
            if process
                .command
                .as_deref()
                .is_some_and(|command| lower(command).contains(&lower(marker)))
            {
                add_ancestors(&mut protected, process.pid, &by_pid);
            }
        }
    }

    let mut root_for = HashMap::new();
    for process in &items {
        let mut cursor = *process;
        let mut seen = HashSet::new();
        while seen.insert(cursor.pid) {
            let Some(parent) = by_pid.get(&cursor.parent_pid).copied() else {
                break;
            };
            if matches!((cursor.created_file_time, parent.created_file_time), (Some(child), Some(parent)) if parent > child)
            {
                break;
            }
            if is_shared_boundary(parent) {
                break;
            }
            cursor = parent;
        }
        root_for.insert(process.pid, cursor.pid);
    }

    let mut families: HashMap<u32, Vec<&Process>> = HashMap::new();
    for process in items {
        families
            .entry(root_for[&process.pid])
            .or_default()
            .push(process);
    }
    let mut roots: Vec<u32> = families.keys().copied().collect();
    roots.sort_unstable();
    roots.into_iter().map(|root_pid| {
        let mut members = families.remove(&root_pid).unwrap_or_default();
        members.sort_by_key(|process| process.pid);
        let root = by_pid[&root_pid];
        let protection = members.iter().find_map(|process| {
            protected.contains(&process.pid).then_some("Protected CLI or requested ancestry")
                .or_else(|| intrinsic_protection(process, current_owner))
        });
        let (classification, reason) = if let Some(reason) = protection {
            (Classification::Protected, reason.to_string())
        } else if members.len() == 1 && known_helper(root) {
            let orphan_reason = if root.parent_pid > 0 && !by_pid.contains_key(&root.parent_pid) {
                Some("Known helper leaf with missing parent")
            } else if root.parent_pid > 0 && by_pid.get(&root.parent_pid).is_some_and(|parent| {
                matches!((parent.created_file_time, root.created_file_time), (Some(parent), Some(child)) if parent > child)
            }) {
                Some("Known helper leaf with reused parent PID")
            } else { None };
            let old_enough = root.created_file_time.is_some_and(|created| now_file_time.saturating_sub(created) > FIVE_MINUTES_FILETIME);
            if old_enough && orphan_reason.is_some() {
                (Classification::Automatic, orphan_reason.unwrap().to_string())
            } else {
                (Classification::Manual, "Insufficient proof for automatic cleanup".to_string())
            }
        } else {
            (Classification::Manual, "Insufficient proof for automatic cleanup".to_string())
        };
        let ticks = root.created_file_time.unwrap_or(0);
        Group {
            id: format!("process:{root_pid}:{ticks}"),
            name: root.name.clone(),
            family: root.name.clone(),
            identities: members.iter().map(|process| Identity {
                pid: process.pid,
                created_file_time: process.created_file_time,
            }).collect(),
            working_set_bytes: members.iter().map(|process| process.working_set_bytes.unwrap_or(0)).sum(),
            classification,
            reason,
        }
    }).collect()
}

fn action_name(classification: Classification, force: bool) -> &'static str {
    match classification {
        Classification::Manual if !force => "Close",
        Classification::Manual => "ForceStop",
        Classification::Automatic => "Stop",
        Classification::Protected => {
            if force {
                "ForceStop"
            } else {
                "Close"
            }
        }
    }
}

fn outcome(group: &Group, action: &str, status: &str, reason: &str) -> Vec<ActionResult> {
    group
        .identities
        .iter()
        .map(|identity| ActionResult {
            pid: identity.pid,
            action: action.to_string(),
            status: status.to_string(),
            reason: reason.to_string(),
        })
        .collect()
}

fn same_identity(process: &Process, identity: &Identity) -> bool {
    process.pid == identity.pid
        && identity.created_file_time.is_some()
        && process.created_file_time == identity.created_file_time
}

fn descendants_appeared(snapshot: &[Process], target: &HashSet<u32>) -> Option<u32> {
    let by_pid: HashMap<u32, &Process> = snapshot
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    for process in snapshot {
        if target.contains(&process.pid) {
            continue;
        }
        let mut cursor = process.parent_pid;
        let mut seen = HashSet::new();
        while cursor > 0 && seen.insert(cursor) {
            if target.contains(&cursor) {
                return Some(process.pid);
            }
            let Some(parent) = by_pid.get(&cursor) else {
                break;
            };
            cursor = parent.parent_pid;
        }
    }
    None
}

fn marker_values() -> Vec<String> {
    ["CODEX_THREAD_ID", "CODEX_SESSION_ID"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
        .collect()
}

pub fn act(group: &Group, force: bool) -> Vec<ActionResult> {
    let action = action_name(group.classification, force);
    if group.classification == Classification::Protected {
        return outcome(
            group,
            action,
            "Refused",
            "Protected groups cannot be stopped",
        );
    }
    let first = match platform::scan() {
        Ok(snapshot) => snapshot,
        Err(error) => return outcome(group, action, "Failed", &format!("Refresh failed: {error}")),
    };
    let observations = if group.classification == Classification::Automatic {
        thread::sleep(Duration::from_secs(2));
        match platform::scan() {
            Ok(second) => vec![first, second],
            Err(error) => {
                return outcome(
                    group,
                    action,
                    "Failed",
                    &format!("Second refresh failed: {error}"),
                )
            }
        }
    } else {
        vec![first]
    };
    let target: HashSet<u32> = group
        .identities
        .iter()
        .map(|identity| identity.pid)
        .collect();
    for snapshot in &observations {
        let by_pid: HashMap<u32, &Process> = snapshot
            .iter()
            .map(|process| (process.pid, process))
            .collect();
        for identity in &group.identities {
            if !by_pid
                .get(&identity.pid)
                .is_some_and(|process| same_identity(process, identity))
            {
                return outcome(
                    group,
                    action,
                    "Stale",
                    "PID is absent or creation identity changed",
                );
            }
        }
        if let Some(pid) = descendants_appeared(snapshot, &target) {
            return outcome(
                group,
                action,
                "Refused",
                &format!("New descendant PID {pid} appeared"),
            );
        }
    }
    let owner = platform::current_owner();
    if owner.as_deref().is_none_or(|value| value.trim().is_empty()) {
        return outcome(
            group,
            action,
            "Refused",
            "Cannot establish current Windows identity",
        );
    }
    let fresh = observations.last().unwrap();
    let fresh_groups = classify(
        fresh,
        std::process::id(),
        owner.as_deref(),
        &marker_values(),
        crate::model::now_file_time(),
    );
    if group.identities.iter().any(|identity| {
        fresh_groups
            .iter()
            .find(|candidate| {
                candidate
                    .identities
                    .iter()
                    .any(|fresh| fresh.pid == identity.pid)
            })
            .is_none_or(|candidate| candidate.classification == Classification::Protected)
    }) {
        return outcome(
            group,
            action,
            "Refused",
            "Refresh classified the target as protected",
        );
    }
    if group.classification == Classification::Automatic {
        if group.identities.len() != 1 {
            return outcome(
                group,
                action,
                "Refused",
                "Automatic cleanup is limited to one exact orphan leaf",
            );
        }
        let pid = group.identities[0].pid;
        let still_automatic = fresh_groups.iter().any(|candidate| {
            candidate.classification == Classification::Automatic
                && candidate.identities.len() == 1
                && candidate.identities[0].pid == pid
        });
        if !still_automatic {
            return outcome(
                group,
                action,
                "Refused",
                "Automatic orphan proof did not survive refresh",
            );
        }
    }
    let terminate = force || group.classification == Classification::Automatic;
    let mut identities = group.identities.clone();
    identities.sort_by_key(|identity| std::cmp::Reverse(identity.pid));
    identities
        .iter()
        .map(|identity| {
            let mut result = platform::stop_exact(identity, terminate, 5);
            result.action = action.to_string();
            result
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: u32, name: &str, age_minutes: u64) -> Process {
        Process {
            pid,
            parent_pid: parent,
            created_file_time: Some(2_000_000_000_000 - age_minutes * 60 * 10_000_000),
            name: name.into(),
            command: Some(String::new()),
            owner: Some("WORKSTATION\\alice".into()),
            session_id: Some(1),
            working_set_bytes: Some(1024),
            ..Process::default()
        }
    }

    fn group_for(groups: &[Group], pid: u32) -> &Group {
        groups
            .iter()
            .find(|group| group.identities.iter().any(|identity| identity.pid == pid))
            .unwrap()
    }

    #[test]
    fn pid_reuse_breaks_parent_link_and_allows_only_old_helper_leaf() {
        let helper = process(10, 11, "chromedriver.exe", 10);
        let parent = process(11, 0, "new-parent.exe", 1);
        let groups = classify(
            &[helper, parent],
            999,
            Some("WORKSTATION\\alice"),
            &[],
            2_000_000_000_000,
        );
        assert_eq!(
            group_for(&groups, 10).classification,
            Classification::Automatic
        );
    }

    #[test]
    fn owner_uncertainty_and_pending_identity_are_protected() {
        let mut unknown = process(20, 999, "chromedriver.exe", 10);
        unknown.owner = None;
        let groups = classify(
            &[unknown],
            9999,
            Some("WORKSTATION\\alice"),
            &[],
            2_000_000_000_000,
        );
        assert_eq!(groups[0].classification, Classification::Protected);
        let groups = classify(
            &[process(21, 999, "chromedriver.exe", 10)],
            9999,
            None,
            &[],
            2_000_000_000_000,
        );
        assert_eq!(groups[0].classification, Classification::Protected);
    }

    #[test]
    fn shared_shell_boundary_does_not_absorb_edge() {
        let shell = process(30, 0, "explorer.exe", 100);
        let edge = process(31, 30, "msedge.exe", 60);
        let edge_child = process(32, 31, "msedge.exe", 50);
        let groups = classify(
            &[shell, edge, edge_child],
            9999,
            Some("WORKSTATION\\alice"),
            &[],
            2_000_000_000_000,
        );
        assert_eq!(
            group_for(&groups, 31).classification,
            Classification::Manual
        );
        assert_eq!(group_for(&groups, 31).identities.len(), 2);
        assert_eq!(
            group_for(&groups, 30).classification,
            Classification::Protected
        );
    }

    #[test]
    fn active_codex_m5_and_thread_marker_are_protected() {
        let codex = process(40, 0, "codex.exe", 60);
        let mut m5 = process(41, 999, "python.exe", 60);
        m5.command = Some("python M5\\run_companion.py".into());
        let mut marked = process(42, 999, "worker.exe", 60);
        marked.command = Some("--thread live-thread".into());
        let groups = classify(
            &[codex, m5, marked],
            9999,
            Some("WORKSTATION\\alice"),
            &["live-thread".into()],
            2_000_000_000_000,
        );
        assert!(groups
            .iter()
            .all(|group| group.classification == Classification::Protected));
    }

    #[test]
    fn automatic_requires_known_old_exact_childless_orphan() {
        let young = process(50, 999, "chromedriver.exe", 5);
        let old = process(51, 998, "chromedriver.exe", 6);
        let parent = process(52, 997, "chromedriver.exe", 20);
        let child = process(53, 52, "unknown.exe", 10);
        let groups = classify(
            &[young, old, parent, child],
            9999,
            Some("WORKSTATION\\alice"),
            &[],
            2_000_000_000_000,
        );
        assert_eq!(
            group_for(&groups, 50).classification,
            Classification::Manual
        );
        assert_eq!(
            group_for(&groups, 51).classification,
            Classification::Automatic
        );
        assert_eq!(
            group_for(&groups, 52).classification,
            Classification::Manual
        );
    }

    #[test]
    fn unknown_low_cpu_never_implies_automatic() {
        let mut unknown = process(60, 999, "mystery.exe", 600);
        unknown.cpu_seconds = Some(0.0);
        let groups = classify(
            &[unknown],
            9999,
            Some("WORKSTATION\\alice"),
            &[],
            2_000_000_000_000,
        );
        assert_eq!(groups[0].classification, Classification::Manual);
    }

    #[test]
    fn force_never_overrides_protected() {
        let group = Group {
            id: "x".into(),
            name: "x".into(),
            family: "x".into(),
            identities: vec![Identity {
                pid: 123,
                created_file_time: Some(1),
            }],
            working_set_bytes: 0,
            classification: Classification::Protected,
            reason: "test".into(),
        };
        let results = act(&group, true);
        assert_eq!(results[0].status, "Refused");
    }

    #[test]
    fn descendant_race_helper_detects_transitive_child() {
        let parent = process(70, 999, "x.exe", 10);
        let child = process(71, 70, "y.exe", 5);
        let grandchild = process(72, 71, "z.exe", 1);
        assert_eq!(
            descendants_appeared(&[parent, child, grandchild], &HashSet::from([70])),
            Some(71)
        );
    }
}

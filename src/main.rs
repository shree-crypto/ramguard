// SPDX-License-Identifier: GPL-3.0-only
mod cache;
mod model;
mod platform;
mod policy;
mod reports;

use clap::{CommandFactory, Parser, Subcommand};
use model::{Classification, Group, Memory, Process};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "ramguard",
    version,
    about = "Local Windows memory diagnosis and guarded cleanup",
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    yes: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    Status,
    Preview,
    Clean,
    Doctor,
    Help,
    Cache {
        #[command(subcommand)]
        action: Option<CacheCommand>,
    },
}

#[derive(Subcommand, Debug)]
enum CacheCommand {
    Preview,
    Clean {
        /// Limit cleanup to exact catalog IDs, e.g. npmCache,pipCache.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
}

fn validate_mutation(json: bool, yes: bool) -> Result<(), String> {
    if json && !yes {
        Err("JSON cleanup requires --yes; JSON mode never prompts.".into())
    } else {
        Ok(())
    }
}

fn parse_selection(value: &str, length: usize) -> Result<Vec<usize>, String> {
    let mut indexes = Vec::new();
    if value.trim().is_empty() {
        return Ok(indexes);
    }
    for part in value.split(',') {
        let number = part
            .trim()
            .parse::<usize>()
            .map_err(|_| "Use comma-separated row numbers.".to_string())?;
        if number == 0 || number > length {
            return Err("Selection is out of range; no selected apps were closed.".into());
        }
        if !indexes.contains(&(number - 1)) {
            indexes.push(number - 1)
        }
    }
    Ok(indexes)
}

fn read_input(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|_| "Cannot display prompt".to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| "Cannot read selection".to_string())?;
    Ok(answer.trim().to_string())
}

fn markers() -> Vec<String> {
    ["CODEX_THREAD_ID", "CODEX_SESSION_ID"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .filter(|s| !s.is_empty())
        .collect()
}

fn groups(processes: &[Process]) -> Vec<Group> {
    let owner = platform::current_owner();
    policy::classify(
        processes,
        std::process::id(),
        owner.as_deref(),
        &markers(),
        model::now_file_time(),
    )
}

fn gib(value: Option<u64>) -> String {
    value
        .map(|v| format!("{:.2} GB", v as f64 / 1_073_741_824.0))
        .unwrap_or_else(|| "unavailable".into())
}

fn show_memory(memory: &Memory) {
    println!(
        "RAM: {} available / {} usable",
        gib(memory.available_bytes),
        gib(memory.total_bytes)
    );
    println!(
        "Kernel pools: nonpaged {}; paged {} (paged pool is not all resident).",
        gib(memory.pool_nonpaged_bytes),
        gib(memory.pool_paged_bytes)
    );
    println!(
        "Committed memory: {} / {} limit (includes pagefile-backed memory).",
        gib(memory.commit_bytes),
        gib(memory.commit_limit_bytes)
    );
}

fn show_groups(groups: &[Group]) {
    println!(
        "{:<7} {:<32} {:>9} {:<11} Reason",
        "Count", "Application", "MB", "Class"
    );
    for group in groups {
        println!(
            "{:<7} {:<32} {:>9.0} {:<11} {}",
            group.identities.len(),
            group.name,
            group.working_set_bytes as f64 / 1_048_576.0,
            format!("{:?}", group.classification).to_lowercase(),
            group.reason
        );
    }
}

fn emit(value: &Value) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "Cannot write JSON output".to_string())?;
    println!();
    Ok(())
}

fn finish_report(mut report: Value, json_mode: bool) -> Result<i32, String> {
    let code = match reports::save(&report, None) {
        Ok(path) => {
            report["Report"] = json!(path);
            0
        }
        Err(error) => {
            report["ReportError"] = json!(error);
            1
        }
    };
    if json_mode {
        emit(&report)?
    } else {
        if let Some(actions) = report.get("Actions") {
            println!("Actions: {}", actions)
        }
        if let Some(results) = report.get("Results") {
            println!("Cache results: {}", results)
        }
        if let Some(before) = report
            .pointer("/Before/AvailableBytes")
            .and_then(Value::as_u64)
        {
            let after = report
                .pointer("/After10Seconds/AvailableBytes")
                .or_else(|| report.pointer("/After/AvailableBytes"))
                .and_then(Value::as_u64);
            println!(
                "Available RAM: {} before; {} after.",
                gib(Some(before)),
                gib(after)
            );
        }
        if let Some(restarts) = report.get("RestartedFamilies").and_then(Value::as_array) {
            if !restarts.is_empty() {
                println!(
                    "Restarted tool families (not killed again): {}",
                    json!(restarts)
                )
            }
        }
        if let Some(path) = report.get("Report") {
            println!("Report: {path}")
        }
        if let Some(error) = report.get("ReportError") {
            eprintln!("Cleanup finished but report could not be saved: {error}")
        }
    }
    Ok(code)
}

fn interactive_groups(manual: &[Group]) -> Result<Vec<usize>, String> {
    if manual.is_empty() {
        println!("No additional user applications are selectable.");
        return Ok(Vec::new());
    }
    let mut offset = 0;
    loop {
        let end = (offset + 20).min(manual.len());
        for (i, group) in manual.iter().enumerate().take(end).skip(offset) {
            println!(
                "[{}] {}: {:.0} MB — {}",
                i + 1,
                group.name,
                group.working_set_bytes as f64 / 1_048_576.0,
                group.reason
            )
        }
        let choice = read_input("App numbers, 'more' for next page, or Enter to skip: ")?;
        if choice == "more" {
            offset = if end == manual.len() { 0 } else { end };
            continue;
        }
        match parse_selection(&choice, manual.len()) {
            Ok(selection) => return Ok(selection),
            Err(error) => eprintln!("{error}"),
        }
    }
}

struct CleanupLock(windows_sys::Win32::Foundation::HANDLE);
impl CleanupLock {
    fn acquire() -> Result<Self, String> {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS},
            System::Threading::CreateMutexW,
        };
        let name: Vec<u16> = "Local\\RamGuard-Native"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err("Cannot acquire cleanup lock.".into());
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err("Another native RamGuard cleanup is running.".into());
        }
        Ok(Self(handle))
    }
}
impl Drop for CleanupLock {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

fn run(cli: Cli) -> Result<i32, String> {
    let started = Instant::now();
    let command = cli.command.unwrap_or(Command::Help);
    if matches!(command, Command::Help) {
        if cli.json {
            emit(
                &json!({"Name":"RamGuard","Version":env!("CARGO_PKG_VERSION"),"Backend":"Rust","Commands":["status","preview","clean","cache preview","cache clean","doctor"],"Options":["--json","--yes"]}),
            )?
        } else {
            Cli::command()
                .print_help()
                .map_err(|_| "Cannot display help".to_string())?;
            println!()
        }
        return Ok(0);
    }
    let mutating = matches!(
        command,
        Command::Clean
            | Command::Cache {
                action: Some(CacheCommand::Clean { .. })
            }
    );
    if mutating {
        validate_mutation(cli.json, cli.yes)?;
        if !cli.yes && !io::stdin().is_terminal() {
            return Err(
                "Interactive input unavailable; use --yes for verified automatic cleanup.".into(),
            );
        }
    }
    let _guard = if mutating {
        Some(CleanupLock::acquire()?)
    } else {
        None
    };
    if let Command::Cache { action } = command {
        let mut roots = cache::roots();
        let mut preview = cache::preview(&roots);
        if !matches!(action, Some(CacheCommand::Clean { .. })) {
            if cli.json {
                emit(
                    &json!({"Caches":preview,"Notice":"Logical sizes can differ from actual filesystem space recovered.","ElapsedMilliseconds":started.elapsed().as_millis()}),
                )?
            } else {
                for row in &preview {
                    println!(
                        "{}: {} bytes; eligible={} — {}",
                        row.id, row.logical_bytes, row.eligible, row.reason
                    )
                }
            }
            return Ok(0);
        }
        if let Some(CacheCommand::Clean { only }) = &action {
            if !only.is_empty() {
                if only
                    .iter()
                    .any(|id| !roots.iter().any(|root| root.id == *id))
                {
                    return Err("Unknown cache catalog ID; nothing deleted.".into());
                }
                roots.retain(|root| only.contains(&root.id));
                preview.retain(|row| only.contains(&row.id));
            }
        }
        if !cli.yes {
            for (i, row) in preview.iter().enumerate() {
                println!(
                    "[{}] {}: {} bytes; eligible={} — {}",
                    i + 1,
                    row.name,
                    row.logical_bytes,
                    row.eligible,
                    row.reason
                )
            }
            let answer = read_input("Cache row numbers, 'all', or Enter to skip: ")?;
            if answer.is_empty() {
                return Ok(0);
            }
            if answer != "all" {
                let selected = parse_selection(&answer, roots.len())?;
                roots = selected
                    .into_iter()
                    .map(|index| roots[index].clone())
                    .collect()
            }
        }
        let before = platform::memory();
        let results = cache::clean(&roots);
        let after = platform::memory();
        return finish_report(
            json!({"Operation":"cache clean","Before":before,"After":after,"Results":results,"ElapsedMilliseconds":started.elapsed().as_millis()}),
            cli.json,
        );
    }
    let before = platform::memory();
    let processes = platform::scan()?;
    let all = groups(&processes);
    if matches!(
        command,
        Command::Status | Command::Preview | Command::Doctor
    ) {
        let mut ordered = all.clone();
        ordered.sort_by_key(|g| std::cmp::Reverse(g.working_set_bytes));
        if !matches!(command, Command::Preview) {
            ordered.truncate(10)
        }
        let mut supervisors = BTreeMap::<String, usize>::new();
        if matches!(command, Command::Doctor) {
            for process in &processes {
                if matches!(
                    process.name.to_lowercase().as_str(),
                    "node.exe" | "node_repl.exe" | "python.exe" | "pythonw.exe"
                ) {
                    let parent = processes
                        .iter()
                        .find(|p| p.pid == process.parent_pid)
                        .map(|p| p.name.as_str())
                        .unwrap_or("not found");
                    *supervisors
                        .entry(format!("{} / {}", process.name, parent))
                        .or_default() += 1;
                }
            }
        }
        let tool = processes.iter().find(|p| p.pid == std::process::id());
        if cli.json {
            emit(
                &json!({"Memory":before,"Groups":ordered,"ToolSupervisors":supervisors,"UnattributedBytes":null,"Attribution":"Working sets overlap; exact physical attribution unavailable.","Backend":"Rust","ToolWorkingSetBytes":tool.and_then(|p|p.working_set_bytes),"ElapsedMilliseconds":started.elapsed().as_millis()}),
            )?
        } else {
            show_memory(&before);
            show_groups(&ordered);
            for (pair, count) in supervisors {
                println!("{count} tools: {pair}")
            }
            println!(
                "Working sets overlap. Unknown ownership is protected or manual. Scan: {} ms.",
                started.elapsed().as_millis()
            )
        }
        return Ok(0);
    }
    let mut actions = Vec::new();
    let mut closed = Vec::new();
    for group in all
        .iter()
        .filter(|g| g.classification == Classification::Automatic)
    {
        let result = policy::act(group, false);
        if result
            .iter()
            .any(|r| r.status == "Stopped" || r.status == "Closed")
        {
            closed.push(group.clone())
        }
        actions.extend(result);
    }
    if !cli.yes {
        let mut manual: Vec<Group> = groups(&platform::scan()?)
            .into_iter()
            .filter(|g| g.classification == Classification::Manual)
            .collect();
        manual.sort_by_key(|g| std::cmp::Reverse(g.working_set_bytes));
        for index in interactive_groups(&manual)? {
            let group = &manual[index];
            let result = policy::act(group, false);
            if result
                .iter()
                .any(|r| r.status == "Stopped" || r.status == "Closed")
            {
                closed.push(group.clone())
            }
            actions.extend(result);
            let fresh = platform::scan()?;
            let survivors = group.identities.iter().any(|identity| {
                fresh.iter().any(|p| {
                    p.pid == identity.pid && p.created_file_time == identity.created_file_time
                })
            });
            if survivors
                && read_input(&format!(
                    "Force-close {}? Unsaved work may be lost. Type FORCE: ",
                    group.name
                ))? == "FORCE"
            {
                let result = policy::act(group, true);
                if result
                    .iter()
                    .any(|r| r.status == "Stopped" || r.status == "Closed")
                {
                    closed.push(group.clone())
                }
                actions.extend(result);
            }
        }
    }
    std::thread::sleep(Duration::from_secs(3));
    let after3 = platform::memory();
    let restart3 = reports::restarted(&closed, &all, &groups(&platform::scan()?));
    std::thread::sleep(Duration::from_secs(7));
    let after10 = platform::memory();
    let restart10 = reports::restarted(&closed, &all, &groups(&platform::scan()?));
    finish_report(
        json!({"Operation":"clean","Before":before,"After3Seconds":after3,"After10Seconds":after10,"Actions":actions,"RestartedFamilies":restart10,"RestartedAt3Seconds":restart3,"ElapsedMilliseconds":started.elapsed().as_millis()}),
        cli.json,
    )
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os()
        .map(|arg| match arg.to_str() {
            Some("-Yes") => "--yes".into(),
            Some("-Json") => "--json".into(),
            _ => arg,
        })
        .collect();
    let json_mode = args.iter().any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                print!("{error}");
                return;
            }
            if json_mode {
                let _ = emit(&json!({"Error":error.to_string()}));
            } else {
                eprintln!("{error}")
            }
            std::process::exit(2)
        }
    };
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if json_mode {
                let _ = emit(&json!({"Error":error}));
            } else {
                eprintln!("ramguard: {error}")
            }
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_mutations_require_explicit_yes() {
        assert!(validate_mutation(true, false).is_err());
        assert!(validate_mutation(true, true).is_ok());
        assert!(validate_mutation(false, false).is_ok());
    }
    #[test]
    fn selection_rejects_zero_outside_and_invalid_rows() {
        assert!(parse_selection("0", 3).is_err());
        assert!(parse_selection("4", 3).is_err());
        assert!(parse_selection("all", 3).is_err());
        assert_eq!(parse_selection("1, 3, 1", 3).unwrap(), vec![0, 2]);
    }
    #[test]
    fn command_lines_never_serialize() {
        let process = Process {
            command: Some("private-secret-content".into()),
            ..Process::default()
        };
        let serialized = serde_json::to_string(&process).unwrap();
        assert!(!serialized.contains("private-secret-content"));
        assert!(!serialized.contains("\"Command\""));
    }
    #[test]
    fn parser_accepts_nested_cache_and_global_flags() {
        let cli = Cli::try_parse_from(["ramguard", "cache", "clean", "--json", "--yes"]).unwrap();
        assert!(cli.json && cli.yes);
        assert!(matches!(
            cli.command,
            Some(Command::Cache {
                action: Some(CacheCommand::Clean { .. })
            })
        ));
        assert!(Cli::try_parse_from(["ramguard", "clean", "--anything"]).is_err());
    }
}

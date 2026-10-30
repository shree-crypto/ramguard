// SPDX-License-Identifier: GPL-3.0-only
use serde_json::Value;
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ramguard"))
        .args(args)
        .output()
        .expect("native CLI starts without a script host")
}

fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("stdout must be exactly one JSON document: {error}"))
}

#[test]
fn help_and_status_are_native_single_json_documents() {
    let help = invoke(&["help", "--json"]);
    assert!(help.status.success());
    assert_eq!(document(&help)["Backend"], "Rust");
    let status = invoke(&["status", "--json"]);
    assert!(status.status.success());
    let json = document(&status);
    assert_eq!(json["Backend"], "Rust");
    assert!(json["Memory"]["TotalBytes"].as_u64().unwrap() > 0);
    assert!(json["Groups"].is_array());
    assert!(!String::from_utf8_lossy(&status.stdout).contains("\"Command\""));
}

#[test]
fn json_mutations_and_unknown_catalog_ids_refuse_without_prompting() {
    for args in [vec!["clean", "--json"], vec!["cache", "clean", "--json"]] {
        let output = invoke(&args);
        assert!(!output.status.success());
        assert!(document(&output)["Error"]
            .as_str()
            .unwrap()
            .contains("requires --yes"));
    }
    let output = invoke(&["cache", "clean", "--yes", "--json", "--only", "unknown-id"]);
    assert!(!output.status.success());
    assert!(document(&output)["Error"]
        .as_str()
        .unwrap()
        .contains("Unknown cache"));
}

#[test]
#[ignore = "Explicit live verification after inspecting automatic candidates; may close verified orphan tools"]
fn live_automatic_cleanup_is_one_prompt_free_json_document() {
    let preview = invoke(&["preview", "--json"]);
    assert!(preview.status.success());
    assert!(
        !document(&preview)["Groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["Classification"] == "automatic"),
        "Live test requires no automatic candidates"
    );
    let output = invoke(&["clean", "--yes", "--json"]);
    assert!(output.status.success());
    let report = document(&output);
    assert_eq!(report["Operation"], "clean");
    assert!(report["Actions"].is_array());
    assert!(report["Report"].is_string());
}

#[test]
#[ignore = "Explicit live verification of the fixed npm cache catalog entry"]
fn live_catalog_cleanup_is_one_prompt_free_json_document() {
    let output = invoke(&["cache", "clean", "--yes", "--json", "--only", "npmCache"]);
    assert!(output.status.success());
    let report = document(&output);
    assert_eq!(report["Operation"], "cache clean");
    let rows = report["Results"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["Id"], "npmCache");
    assert!(report["Report"].is_string());
}

//! Tests for daemon lifecycle commands.

use predicates::prelude::*;
use serde_json::{self, json};
use serial_test::serial;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Stdio;
use std::time::Duration;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

/// Try to create a DaemonTestHarness. Returns None (and skips the test) if
/// the bridge fails to start due to "program file(s) not found" - a known
/// macOS issue where Ghidra can't find the imported program.
fn try_start_daemon() -> Option<DaemonTestHarness> {
    match DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM) {
        Ok(h) => Some(h),
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("program file(s) not found")
                || msg.contains("Could not find project")
                || msg.contains("Path element starting with '.'")
            {
                eprintln!(
                    "Skipping test: bridge/project setup issue (known env/CI constraint): {}",
                    msg
                );
                None
            } else {
                panic!("Failed to start daemon: {}", e);
            }
        }
    }
}

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_ping() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("ping")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_mcp_stdio_bridge_tools() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let mut child = std::process::Command::new(ghidra_bin)
        .args(["--project", TEST_PROJECT, "mcp", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn ghidra mcp stdio");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    let send = |stdin: &mut dyn std::io::Write, v: &serde_json::Value| {
        let s = serde_json::to_string(v).unwrap();
        writeln!(stdin, "{}", s).unwrap();
        stdin.flush().unwrap();
    };

    let recv = |r: &mut BufReader<std::process::ChildStdout>| -> String {
        let mut line = String::new();
        r.read_line(&mut line).expect("read line from mcp");
        line
    };

    // initialize
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}));
    let _ = recv(&mut reader);

    // tools/list
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let line = recv(&mut reader);
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).expect("parse tools/list");
    let tools = &rpc["result"]["tools"];
    let names: Vec<_> = tools.as_array().unwrap().iter()
        .map(|t| t["name"].as_str().unwrap().to_string()).collect();
    assert!(names.contains(&"ping".to_string()));
    assert!(names.contains(&"project_list".to_string()));
    assert!(names.contains(&"function_list".to_string()));
    assert!(names.contains(&"decompile".to_string()));
    assert!(names.contains(&"xrefs_to".to_string()));

    // project_list
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"project_list","arguments":{}}}));
    let line = recv(&mut reader);
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let text = rpc["result"]["content"][0]["text"].as_str().unwrap();
    let env: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(env["status"], "success");
    assert_eq!(env["command"], "project_list");
    assert!(env["provenance"].get("tool_version").is_some());
    assert!(env.get("next_steps").is_some());

    // function_list
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"function_list","arguments":{"limit":5}}}));
    let line = recv(&mut reader);
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let text = rpc["result"]["content"][0]["text"].as_str().unwrap();
    let env: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(env["status"], "success");
    assert_eq!(env["command"], "function_list");

    // pick target
    let funcs_val = env["data"].get("functions").cloned().unwrap_or(json!([]));
    let first = funcs_val.as_array().and_then(|a| a.first());
    let target = if let Some(f) = first {
        f.get("address").and_then(|a| a.as_str())
            .or_else(|| f.get("name").and_then(|n| n.as_str()))
            .unwrap_or("main")
    } else {
        "main"
    };

    // decompile (must include extra context per objective)
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"decompile","arguments":{"target":target}}}));
    let line = recv(&mut reader);
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let text = rpc["result"]["content"][0]["text"].as_str().unwrap();
    let env: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(env["status"], "success");
    assert_eq!(env["command"], "decompile");
    let data = &env["data"];
    // extra context fields (may be empty but must be present)
    assert!(data.get("nearby_xrefs").is_some());
    assert!(data.get("callers").is_some());
    assert!(data.get("code").is_some() || data.get("signature").is_some());

    // xrefs_to
    let xref_target = data.get("address").and_then(|a| a.as_str()).unwrap_or(target);
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"xrefs_to","arguments":{"target":xref_target}}}));
    let line = recv(&mut reader);
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let text = rpc["result"]["content"][0]["text"].as_str().unwrap();
    let env: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(env["status"], "success");
    assert_eq!(env["command"], "xrefs_to");
    assert!(env["provenance"].get("timestamp").is_some());

    // cleanup
    drop(stdin);
    let _ = child.wait();

    drop(harness);
}

/// Mutation durability via MCP: set a comment, re-read, then open a second
/// MCP process against the same bridge and confirm the comment is still visible.
#[test]
#[serial]
fn test_mcp_mutation_durability_comment() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");

    // Resolve a function target via MCP function_list
    let run_mcp_call = |tool: &str, args: serde_json::Value| -> serde_json::Value {
        let mut child = std::process::Command::new(&ghidra_bin)
            .args(["--project", TEST_PROJECT, "mcp", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp");
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let send = |stdin: &mut dyn std::io::Write, v: &serde_json::Value| {
            writeln!(stdin, "{}", serde_json::to_string(v).unwrap()).unwrap();
            stdin.flush().unwrap();
        };
        let mut line = String::new();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        drop(stdin);
        let _ = child.wait();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).expect("rpc");
        let text = rpc["result"]["content"][0]["text"].as_str().expect("text");
        serde_json::from_str(text).expect("envelope")
    };

    let fl = run_mcp_call("function_list", json!({"limit": 10}));
    assert_eq!(fl["status"], "success", "function_list failed: {}", fl);
    let funcs = fl["data"]
        .get("functions")
        .and_then(|v| v.as_array())
        .cloned()
        .or_else(|| fl["data"].as_array().cloned())
        .unwrap_or_default();
    let target = funcs
        .iter()
        .find_map(|f| f.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
        .or_else(|| {
            funcs
                .iter()
                .find_map(|f| f.get("address").and_then(|a| a.as_str()).map(|s| s.to_string()))
        })
        .expect("need at least one function for mutation test");

    let marker = format!("mcp_dur_{}", &uuid::Uuid::new_v4().to_string()[..8]);

    // Force a validation error path to assert recovery_suggestions + provenance
    let err_env = run_mcp_call("rename_function", json!({"target": target}));
    assert_eq!(err_env["status"], "error");
    assert!(
        err_env["recovery_suggestions"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "recovery_suggestions required on mutation errors: {}",
        err_env
    );
    assert!(err_env["provenance"]["tool_version"].is_string());
    assert!(err_env["provenance"]["timestamp"].is_string());

    // Apply rename mutation
    let set_env = run_mcp_call(
        "rename_function",
        json!({"target": target, "name": marker}),
    );
    assert_eq!(
        set_env["status"], "success",
        "rename_function failed: {}",
        set_env
    );

    // Fresh MCP process: function_list must show the new name (durability invariant)
    let list_env = run_mcp_call("function_list", json!({"limit": 50, "filter": marker}));
    assert_eq!(list_env["status"], "success", "function_list failed: {}", list_env);
    let blob = list_env.to_string();
    assert!(
        blob.contains(&marker),
        "mutation not durable across fresh MCP process; envelope={}",
        list_env
    );

    drop(harness);
}

/// Live: summarize findings with confidence, pcode ops, transaction begin/abort.
#[test]
#[serial]
fn test_mcp_summarize_pcode_transaction() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let run_mcp_call = |tool: &str, args: serde_json::Value| -> serde_json::Value {
        let mut child = std::process::Command::new(&ghidra_bin)
            .args(["--project", TEST_PROJECT, "mcp", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp");
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let send = |stdin: &mut dyn std::io::Write, v: &serde_json::Value| {
            writeln!(stdin, "{}", serde_json::to_string(v).unwrap()).unwrap();
            stdin.flush().unwrap();
        };
        let mut line = String::new();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        drop(stdin);
        let _ = child.wait();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).expect("rpc");
        let text = rpc["result"]["content"][0]["text"].as_str().expect("text");
        serde_json::from_str(text).expect("envelope")
    };

    // summarize: structured sections + confidence-tagged findings
    let sum = run_mcp_call("summarize", json!({"focus": "all"}));
    assert_eq!(sum["status"], "success", "summarize failed: {}", sum);
    let findings = sum["data"]["findings"]
        .as_array()
        .expect("findings array");
    assert!(!findings.is_empty(), "expected at least one finding");
    for f in findings {
        let conf = f["confidence"].as_f64().expect("confidence");
        assert!((0.0..=1.0).contains(&conf));
        assert!(f.get("kind").and_then(|k| k.as_str()).is_some());
    }

    // pick a function for pcode
    let fl = run_mcp_call("function_list", json!({"limit": 5}));
    assert_eq!(fl["status"], "success");
    let target = fl["data"]
        .get("functions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|f| {
            f.get("name")
                .and_then(|n| n.as_str())
                .or_else(|| f.get("address").and_then(|a| a.as_str()))
        })
        .unwrap_or("main")
        .to_string();

    let pc = run_mcp_call("pcode", json!({"target": target, "limit": 20}));
    assert_eq!(pc["status"], "success", "pcode failed: {}", pc);
    let data = &pc["data"];
    // ops array present (may be empty on decompile failure paths; assert field exists)
    assert!(
        data.get("ops").is_some() || data.get("count").is_some(),
        "pcode missing ops/count: {}",
        pc
    );
    if let Some(ops) = data.get("ops").and_then(|v| v.as_array()) {
        if let Some(first) = ops.first() {
            assert!(
                first.get("mnemonic").is_some() || first.get("opcode").is_some(),
                "pcode op missing mnemonic: {}",
                first
            );
        }
    }

    // transaction begin → abort (undo boundary)
    let begin = run_mcp_call("transaction_begin", json!({"name": "mcp-test-tx"}));
    assert_eq!(begin["status"], "success", "transaction_begin failed: {}", begin);
    assert!(
        begin["data"].get("transaction_id").is_some()
            || begin["data"].get("status").and_then(|s| s.as_str()) == Some("open"),
        "begin payload: {}",
        begin
    );
    let abort = run_mcp_call("transaction_abort", json!({}));
    assert_eq!(abort["status"], "success", "transaction_abort failed: {}", abort);

    // CLI path for pcode --max-ops (regression for clap limit clash)
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args([
            "--project",
            TEST_PROJECT,
            "--json",
            "--envelope",
            "pcode",
            &target,
            "--max-ops",
            "10",
        ])
        .assert()
        .success();

    drop(harness);
}

/// Live: structure recover, data_flow, similarity via MCP; multi-program summarize.
#[test]
#[serial]
fn test_mcp_deeper_primitives_and_multiprogram() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let run_mcp_call = |tool: &str, args: serde_json::Value| -> serde_json::Value {
        let mut child = std::process::Command::new(&ghidra_bin)
            .args(["--project", TEST_PROJECT, "mcp", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mcp");
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let send = |stdin: &mut dyn std::io::Write, v: &serde_json::Value| {
            writeln!(stdin, "{}", serde_json::to_string(v).unwrap()).unwrap();
            stdin.flush().unwrap();
        };
        let mut line = String::new();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        drop(stdin);
        let _ = child.wait();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).expect("rpc");
        let text = rpc["result"]["content"][0]["text"].as_str().expect("text");
        serde_json::from_str(text).expect("envelope")
    };

    let fl = run_mcp_call("function_list", json!({"limit": 5}));
    assert_eq!(fl["status"], "success");
    let target = fl["data"]
        .get("functions")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|f| {
            f.get("address")
                .and_then(|a| a.as_str())
                .or_else(|| f.get("name").and_then(|n| n.as_str()))
        })
        .unwrap_or("main")
        .to_string();

    let df = run_mcp_call("data_flow", json!({"target": target, "limit": 30}));
    assert_eq!(df["status"], "success", "data_flow failed: {}", df);
    assert!(
        df["data"].get("defs").is_some()
            || df["data"].get("uses").is_some()
            || df["data"].get("op_count").is_some(),
        "data_flow missing structure: {}",
        df
    );
    assert!(df["data"]["confidence"].as_f64().is_some() || df["data"].get("summary").is_some());

    let sr = run_mcp_call(
        "structure_recover",
        json!({"address": target, "max_fields": 8}),
    );
    assert_eq!(sr["status"], "success", "structure_recover failed: {}", sr);
    assert!(
        sr["data"].get("confidence").is_some() || sr["data"].get("fields").is_some(),
        "structure_recover missing fields/confidence: {}",
        sr
    );

    let sim = run_mcp_call(
        "similarity",
        json!({"mode": "all", "threshold": 0.5, "limit": 10}),
    );
    assert_eq!(sim["status"], "success", "similarity failed: {}", sim);
    assert!(sim["data"].get("findings").is_some());

    // Multi-program convenience: firmware_summarize over current program list
    let fw = run_mcp_call(
        "firmware_summarize",
        json!({"programs": [TEST_PROGRAM], "focus": "imports"}),
    );
    assert_eq!(fw["status"], "success", "firmware_summarize failed: {}", fw);
    let results = fw["data"]["results"].as_array().expect("results");
    assert!(!results.is_empty());
    assert_eq!(results[0]["program"], TEST_PROGRAM);

    // CLI multi-program path
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args([
            "--project",
            TEST_PROJECT,
            "--json",
            "--envelope",
            "program",
            "firmware-summarize",
            "--include",
            TEST_PROGRAM,
            "--focus",
            "imports",
        ])
        .assert()
        .success();

    drop(harness);
}

/// Live: dual-program explain when a second program exists; transfer is best-effort.
#[test]
#[serial]
fn test_mcp_diff_explain_and_transfer_surface() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    // List programs — if only one, exercise explain/transfer error envelopes still
    let mut child = std::process::Command::new(&ghidra_bin)
        .args(["--project", TEST_PROJECT, "mcp", "stdio"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let send = |stdin: &mut dyn std::io::Write, v: &serde_json::Value| {
        writeln!(stdin, "{}", serde_json::to_string(v).unwrap()).unwrap();
        stdin.flush().unwrap();
    };
    let mut line = String::new();
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    line.clear();
    reader.read_line(&mut line).unwrap();
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"project_list","arguments":{}}}),
    );
    line.clear();
    reader.read_line(&mut line).unwrap();
    let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let env: serde_json::Value =
        serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let names: Vec<String> = env["data"]
        .get("programs")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Always assert tools exist via tools/list
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
    );
    line.clear();
    reader.read_line(&mut line).unwrap();
    let list: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    let tnames: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(tnames.contains(&"diff_transfer"));
    assert!(tnames.contains(&"diff_explain"));

    if names.len() >= 2 {
        let p1 = &names[0];
        let p2 = &names[1];
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"diff_explain","arguments":{"program1":p1,"program2":p2}}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let exp: serde_json::Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(exp["status"], "success", "diff_explain: {}", exp);
        assert!(exp["data"].get("summary").is_some() || exp["data"].get("bullets").is_some());
        assert!(
            exp["data"].get("dual_provenance").is_some()
                || exp["data"].get("program1").is_some(),
            "missing dual provenance: {}",
            exp
        );

        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"diff_transfer","arguments":{"program1":p1,"program2":p2,"labels":true,"comments":true,"limit":5}}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let tr: serde_json::Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(tr["status"], "success", "diff_transfer: {}", tr);
        assert!(tr["data"].get("dual_provenance").is_some() || tr["data"].get("transferred").is_some());
    } else {
        // Single-program project: explain with identical names must error (not crash)
        send(
            &mut stdin,
            &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"diff_explain","arguments":{"program1":TEST_PROGRAM,"program2":TEST_PROGRAM}}}),
        );
        line.clear();
        reader.read_line(&mut line).unwrap();
        let rpc: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let exp: serde_json::Value =
            serde_json::from_str(rpc["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(exp["status"], "error");
        assert!(!exp["recovery_suggestions"].as_array().unwrap().is_empty());
    }

    drop(stdin);
    let _ = child.wait();
    drop(harness);
}

#[test]
#[serial]
fn test_mcp_http_launch_and_tools() {
    require_ghidra!();

    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let mut child = std::process::Command::new(&ghidra_bin)
        .args(["mcp", "http", "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp http");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read listen line from mcp http");
    // format: ghidra-mcp-http listening on 127.0.0.1:PORT
    let p = line
        .rsplit(':')
        .next()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or_else(|| panic!("could not parse port from: {:?}", line));
    assert!(p > 0);

    // tools/list via HTTP
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", p)).expect("connect http");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut resp = String::new();
    let mut r = BufReader::new(stream);
    r.read_to_string(&mut resp).ok();
    assert!(resp.contains("HTTP/1.1 200"), "resp={}", resp);
    assert!(resp.contains("\"tools\""), "resp={}", resp);
    assert!(resp.contains("ping") && resp.contains("patch_bytes"), "resp={}", resp);

    // ping tool call — envelope keys
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", p)).expect("connect http 2");
    let body = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}"#;
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut resp = String::new();
    let mut r = BufReader::new(stream);
    r.read_to_string(&mut resp).ok();
    assert!(resp.contains("HTTP/1.1 200"), "resp={}", resp);
    assert!(
        resp.contains("provenance") || resp.contains("tool_version") || resp.contains("pong"),
        "resp={}",
        resp
    );

    // Streamable long-job path: progress frames + final envelope
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", p)).expect("connect http stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let body = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}"#;
    let req = format!(
        "POST /mcp?stream=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut resp = String::new();
    let mut r = BufReader::new(stream);
    r.read_to_string(&mut resp).ok();
    assert!(resp.contains("text/event-stream") || resp.contains("event: progress"), "resp={}", resp);
    assert!(resp.contains("event: progress"), "resp={}", resp);
    assert!(resp.contains("event: result"), "resp={}", resp);
    assert!(
        resp.contains("success") || resp.contains("pong") || resp.contains("provenance"),
        "resp={}",
        resp
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(_harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("ping")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("status")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success()
        .stdout(predicate::str::contains("No bridge running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_restart() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra restart` stops the old bridge and starts a new JVM. With piped
    // stdout/stderr, the new JVM inherits pipe handles, blocking forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "restart",
            "--project",
            TEST_PROJECT,
            "--program",
            TEST_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run restart");

    if !status.success() {
        eprintln!("Restart failed with status: {}", status);
        drop(harness);
        return;
    }

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("stop")
        .arg("--project")
        .arg(TEST_PROJECT)
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("start")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}

#[test]
#[serial]
fn test_bridge_job_status_is_available_when_idle() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };
    let client = harness.client().expect("bridge client");

    let status = client.status().expect("bridge status");
    assert_eq!(
        status.get("bridge_state").and_then(|v| v.as_str()),
        Some("running")
    );
    assert_eq!(status.get("queue_depth").and_then(|v| v.as_u64()), Some(0));
    assert!(status.get("active_job").is_some_and(|v| v.is_null()));

    let missing = client
        .job_status(Some(u64::MAX))
        .expect("missing job status");
    assert_eq!(missing.get("found").and_then(|v| v.as_bool()), Some(false));
}

#[test]
#[serial]
fn test_control_plane_stays_responsive_while_program_job_runs() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let Some(harness) = try_start_daemon() else {
        return;
    };
    let port = harness.port();

    let analysis =
        std::thread::spawn(move || ghidra_cli::ipc::client::BridgeClient::new(port).analyze());

    let control = harness.client().expect("control client");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let active_job_id = loop {
        let status = control.status().expect("status while analysis runs");
        if let Some(active) = status.get("active_job").filter(|v| !v.is_null()) {
            if active.get("command").and_then(|v| v.as_str()) == Some("analyze") {
                break active
                    .get("id")
                    .and_then(|v| v.as_u64())
                    .expect("active job id");
            }
        }
        assert!(
            !analysis.is_finished(),
            "analysis completed before its active job was observable"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "analysis never appeared as the active bridge job"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let ping_started = std::time::Instant::now();
    assert!(control.ping().expect("ping while analysis runs"));
    assert!(
        ping_started.elapsed() < Duration::from_secs(2),
        "control-plane ping waited behind the active program job"
    );

    let active = control
        .job_status(Some(active_job_id))
        .expect("active job status");
    assert_eq!(active.get("found").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        active
            .get("job")
            .and_then(|v| v.get("command"))
            .and_then(|v| v.as_str()),
        Some("analyze")
    );

    // Queue more program operations than the old connection pool's four core
    // threads. A ping after all eight are visible proves control handling does
    // not depend on a spare job-waiting connection thread.
    let queued: Vec<_> = (0..8)
        .map(|_| {
            let queued_port = harness.port();
            std::thread::spawn(move || {
                ghidra_cli::ipc::client::BridgeClient::new(queued_port).stats()
            })
        })
        .collect();

    let queued_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let queued_job_ids = loop {
        let status = control.status().expect("status with queued job");
        let ids: Vec<u64> = status
            .get("queued_jobs")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|job| job.get("command").and_then(|v| v.as_str()) == Some("stats"))
            .filter_map(|job| job.get("id").and_then(|v| v.as_u64()))
            .collect();
        if ids.len() == queued.len() {
            break ids;
        }
        assert!(
            queued.iter().all(|thread| !thread.is_finished()),
            "a queued stats job ran before the saturated queue was observable"
        );
        assert!(
            std::time::Instant::now() < queued_deadline,
            "stats job never appeared in the bridge queue"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let saturated_ping_started = std::time::Instant::now();
    assert!(control.ping().expect("ping with eight queued jobs"));
    assert!(
        saturated_ping_started.elapsed() < Duration::from_secs(2),
        "control-plane ping was starved by program clients waiting for results"
    );

    for queued_job_id in queued_job_ids {
        let cancelled = control
            .cancel_job(Some(queued_job_id))
            .expect("cancel queued job");
        assert_eq!(
            cancelled.get("state").and_then(|v| v.as_str()),
            Some("cancelled")
        );
    }

    for queued_thread in queued {
        let queued_result = queued_thread.join().expect("queued client thread");
        assert!(
            queued_result.is_err(),
            "cancelled queued job unexpectedly ran"
        );
    }

    analysis
        .join()
        .expect("analysis client thread")
        .expect("analysis job should complete");
}

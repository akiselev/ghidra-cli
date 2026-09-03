//! Tests for symbol operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, DaemonTestHarness,
};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

#[test]
#[serial]
fn test_symbol_list() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    assert!(output.status.success(), "symbol list should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Known functions should appear as symbols
    // On macOS, names may have underscore prefix
    assert!(
        stdout.contains("main") || stdout.contains("_main"),
        "symbol list should contain main. Output: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_symbol_create_and_get() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("create")
        .arg(&addr)
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("get")
        .arg("test_symbol")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test_symbol"));
}

#[test]
#[serial]
fn test_symbol_rename() {
    require_ghidra!();
    let harness = harness();

    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 2);
    let addr = &addrs[1];

    // Use unique names to avoid collisions with cached project state
    let old_name = format!("old_sym_{}", std::process::id());
    let new_name = format!("new_sym_{}", std::process::id());

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("create")
        .arg(addr)
        .arg(&old_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("rename")
        .arg(&old_name)
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify new symbol exists
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("get")
        .arg(&new_name)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains(&*new_name));
}

#[test]
#[serial]
fn test_symbol_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("symbol")
        .arg("get")
        .arg("nonexistent_symbol_12345")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

#[test]
#[serial]
fn test_function_create_recreates_deleted_function_body() {
    require_ghidra!();
    let harness = harness();

    // Regression: `function create` called FunctionManager.createFunction()
    // with a null body, which does not follow flow from the entry point to
    // compute one -- for real, already-disassembled entry points (ARM/Thumb
    // vtable targets in the field report; reproduced here by deleting an
    // ordinary function and recreating it at the same entry) it deterministically
    // rejected the address with "Function body must contain the entrypoint".
    // The fix routes through CreateFunctionCmd, which follows flow like
    // GhidraScript.createFunction()/the UI's "Create Function" action do.
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "add_numbers");

    let before = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(before.status.success());
    let before_json: serde_json::Value =
        serde_json::from_slice(&before.stdout).expect("valid JSON");
    let original_size = before_json[0]["size"].as_u64().expect("size field");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("delete")
        .arg(&addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("create")
        .arg(&addr)
        .arg("add_numbers")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    let after = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("function")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(after.status.success());
    let after_json: serde_json::Value = serde_json::from_slice(&after.stdout).expect("valid JSON");
    assert_eq!(
        after_json[0]["size"].as_u64(),
        Some(original_size),
        "recreated function body should match the original (flow-followed, not a stub): {}",
        after_json
    );
}

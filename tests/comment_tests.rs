//! Tests for comment operations.

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
fn test_comment_set_and_get() {
    require_ghidra!();
    let harness = harness();

    // Dynamically resolve an address with a code unit
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(&addr)
        .arg("test comment from integration test")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Get the comment back
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("get")
        .arg(&addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("test comment"));
}

#[test]
#[serial]
fn test_comment_list() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 2);
    let addr = &addrs[0];

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("another comment")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Analysis generates thousands of auto EOL reference comments at low
    // addresses; `comment list` is address-ordered and limited (default 1000),
    // so a user comment at a high function address can fall outside the default
    // window. Pass an explicit large limit so the assertion is deterministic.
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("list")
        .arg("--limit")
        .arg("100000")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("another comment"));
}

#[test]
#[serial]
fn test_comment_delete() {
    require_ghidra!();
    let harness = harness();

    // Use a dynamically resolved function address
    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 3);
    let addr = &addrs[addrs.len() - 1];

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("set")
        .arg(addr)
        .arg("to be deleted")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("delete")
        .arg(addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify comment is actually gone
    let get_result = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("comment")
        .arg("get")
        .arg(addr)
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&get_result.stdout);
    assert!(
        !get_result.status.success() || !stdout.contains("to be deleted"),
        "Comment should be deleted but was still found: {}",
        stdout
    );
}

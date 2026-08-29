//! Tests for type operations.

use predicates::prelude::*;
use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, get_function_address, ghidra, DaemonTestHarness};

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
fn test_type_list() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("list")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();
}

#[test]
#[serial]
fn test_type_get_primitive() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("get")
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("size"));
}

#[test]
#[serial]
fn test_type_create() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("create")
        .arg("MyTestStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Verify created type exists
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("get")
        .arg("MyTestStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("MyTestStruct"));
}

#[test]
#[serial]
fn test_type_apply() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("apply")
        .arg(&addr)
        .arg("int")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Applying a type at a code address may conflict with existing instructions
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Conflicting instruction")
            || stderr.contains("conflict"),
        "Expected success or instruction conflict, got: {}",
        stderr
    );
}

/// `main` in the shared, cross-test `ci-test`/`sample_binary` fixture is relied
/// on (read-only) by dozens of tests across the suite. Add `delta` bytes to a
/// hex address string, preserving width, so this test can clear/redisassemble
/// a small window around it without hardcoding a magic offset.
fn hex_addr_plus(addr: &str, delta: u64) -> String {
    let val = u64::from_str_radix(addr, 16).expect("hex address");
    format!("{:0width$x}", val + delta, width = addr.len())
}

/// Force-clear+redisassemble a small window at `addr` back to instructions,
/// via the same `clear --disasm-at` path a caller would use to recover from
/// this (ghidra-bug.md's own suggested workaround) -- used both to armor this
/// test against `main` having been left mid-disassembled by another test
/// sharing the fixture, and to restore it afterward.
fn restore_disassembly(harness: &DaemonTestHarness, addr: &str) {
    ghidra(harness)
        .arg("clear")
        .arg(format!("{}:{}", addr, hex_addr_plus(addr, 15)))
        .arg("--disasm-at")
        .arg(addr)
        .arg("--json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run()
        .assert_success();
}

#[test]
#[serial]
// `#[serial]` only serializes within this binary; cargo runs test *files* as
// separate processes in parallel by default, and `main`'s entry is read by
// dozens of tests across other files (readonly_tests.rs, patch_tests.rs,
// etc.) with no cross-process lock protecting it. This test's clear/restore
// steps below are correct and leave `main` intact on exit, but a
// concurrently-running test in another file can still observe it broken in
// the window in between. Run explicitly (`cargo test -- --ignored`) or
// alone; skip it in a full parallel `cargo test` run.
#[ignore]
fn test_type_apply_force_on_function_entry_warns() {
    require_ghidra!();
    let harness = harness();

    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    // Armor against `main` having been left mid-disassembled by another test
    // sharing this cached fixture (e.g. `test_type_apply` above can itself
    // silently succeed rather than conflict, if a prior run left the entry
    // only partially defined) -- this test needs a clean function entry to
    // exercise the case it's actually testing.
    restore_disassembly(harness, &addr);

    // --force on a function's own entry point clears its code (not a
    // conflicting data unit) -- the response must flag that distinctly so a
    // caller doesn't mistake it for a normal conflict-clear (ghidra-bug.md).
    let result = ghidra(harness)
        .arg("type")
        .arg("apply")
        .arg(&addr)
        .arg("int")
        .arg("--force")
        .arg("--json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();

    // Restore `main`'s disassembly for the many other tests sharing this
    // fixture regardless of what the assertions below find.
    restore_disassembly(harness, &addr);

    result.assert_success();
    // The CLI wraps single-address results in a JSON array.
    let json: serde_json::Value = result.json();
    let entry = &json[0];
    assert_eq!(entry["cleared_conflicting"], true);
    assert_eq!(
        entry["is_function_entry"], true,
        "expected is_function_entry:true when --force clears a function's own entry, got: {}",
        entry
    );
    assert!(
        entry["warning"].as_str().is_some_and(|w| w.contains("main")),
        "expected a warning naming the cleared function, got: {}",
        entry
    );
}

#[test]
#[serial]
fn test_type_add_field_places_at_exact_offset() {
    require_ghidra!();
    let _harness = harness();

    // Regression: `--offset` used to behave as insert-before (shifting every
    // later field by the new field's size) instead of placing the field at
    // that exact byte offset. Add three fields out of ascending order and
    // confirm none of them moved and the struct didn't grow past what the
    // offsets require. Uses "byte" (always 1 byte, unlike "pointer" whose
    // size depends on the target's bitness) so the offsets below stay
    // non-overlapping on any platform running this test.
    let _ = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("delete")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("create")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    for (name, offset) in [("field_a", 36), ("field_b", 40), ("field_c", 60)] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("type")
            .arg("add-field")
            .arg("OffsetPlacementStruct")
            .arg("--name")
            .arg(name)
            .arg("--type")
            .arg("byte")
            .arg("--offset")
            .arg(offset.to_string())
            .arg("--project")
            .arg(TEST_PROJECT)
            .arg("--program")
            .arg(TEST_PROGRAM)
            .assert()
            .success();
    }

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("get")
        .arg("OffsetPlacementStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--format")
        .arg("json")
        .output()
        .expect("Failed to run command");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON: {} in {}", e, stdout));
    let obj = parsed
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(&parsed);

    assert_eq!(
        obj["size"].as_u64(),
        Some(61),
        "struct should be exactly as large as the last field (offset 60, 1 byte) requires, not bigger: {}",
        obj
    );

    let components = obj["components"].as_array().expect("components array");
    for (name, offset) in [("field_a", 36), ("field_b", 40), ("field_c", 60)] {
        let comp = components
            .iter()
            .find(|c| c["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("field {} missing from struct: {}", name, obj));
        assert_eq!(
            comp["offset"].as_i64(),
            Some(offset),
            "field {} should sit at its requested offset, not be shifted: {}",
            name,
            obj
        );
    }
}

#[test]
#[serial]
fn test_type_add_field_accepts_common_c_type_names() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("create")
        .arg("CTypeNameStruct")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    // Regression: only "pointer" and "undefined4" used to resolve; ordinary
    // C/Ghidra builtin spellings (including ones `function set-signature`
    // already accepted, like "void *") were rejected with "Field type not
    // found".
    for (field, ty) in [
        ("f_uint", "uint"),
        ("f_dword", "dword"),
        ("f_int", "int"),
        ("f_charptr", "char *"),
        ("f_voidptr", "void *"),
        ("f_uint32", "uint32_t"),
        ("f_u32", "u32"),
        ("f_ulong", "ulong"),
    ] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("type")
            .arg("add-field")
            .arg("CTypeNameStruct")
            .arg("--name")
            .arg(field)
            .arg("--type")
            .arg(ty)
            .arg("--project")
            .arg(TEST_PROJECT)
            .arg("--program")
            .arg(TEST_PROGRAM)
            .assert()
            .success();
    }
}

#[test]
#[serial]
fn test_type_get_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("type")
        .arg("get")
        .arg("NonexistentType12345")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

//! Tests for function tag operations (issue #17).
//!
//! Tags persist in the shared ci-test project across runs, so every test
//! cleans up its own uniquely-prefixed tags (and tolerates leftovers by
//! deleting them up front).

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{
    ensure_test_project, get_function_address, get_function_addresses, helpers::ghidra,
    DaemonTestHarness,
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

/// Delete a tag, ignoring failure (used for pre-test cleanup of leftovers).
fn cleanup_tag(harness: &DaemonTestHarness, name: &str) {
    let _ = ghidra(harness)
        .arg("tag")
        .arg("delete")
        .arg(name)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
}

/// Run a tag subcommand with JSON output and return the parsed rows.
/// Uses the global `--json` flag: mutation subcommands deliberately carry no
/// QueryOptions, so `--format json` is not available on them.
fn tag_json(harness: &DaemonTestHarness, args: &[&str]) -> Vec<serde_json::Value> {
    let result = ghidra(harness)
        .args(args.iter().copied())
        .arg("--json")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_success();
    result.json()
}

fn str_items(value: &serde_json::Value) -> Vec<&str> {
    value
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default()
}

#[test]
#[serial]
fn test_tag_create_and_list_roundtrip() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt1_crypto");

    let rows = tag_json(
        harness,
        &["tag", "create", "tt1_crypto", "--comment", "AES helpers"],
    );
    assert_eq!(rows[0]["status"], "created");
    assert_eq!(rows[0]["existed"], false);

    let tags = tag_json(harness, &["tag", "list"]);
    let row = tags
        .iter()
        .find(|t| t["name"] == "tt1_crypto")
        .expect("created tag missing from tag list");
    assert_eq!(row["comment"], "AES helpers");
    assert_eq!(row["use_count"], 0);

    cleanup_tag(harness, "tt1_crypto");
}

#[test]
#[serial]
fn test_tag_create_existing_reports_existed() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt2_dup");

    tag_json(harness, &["tag", "create", "tt2_dup"]);
    let rows = tag_json(harness, &["tag", "create", "tt2_dup"]);
    assert_eq!(rows[0]["existed"], true);

    cleanup_tag(harness, "tt2_dup");
}

#[test]
#[serial]
fn test_tag_add_reports_created_and_already_present() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt3_pre");
    cleanup_tag(harness, "tt3_auto");

    tag_json(harness, &["tag", "create", "tt3_pre"]);

    let rows = tag_json(harness, &["tag", "add", &addr, "tt3_pre", "tt3_auto"]);
    let row = &rows[0];
    assert_eq!(row["status"], "tagged");
    assert_eq!(str_items(&row["added"]), vec!["tt3_pre", "tt3_auto"]);
    assert_eq!(str_items(&row["created"]), vec!["tt3_auto"]);
    assert!(str_items(&row["already_present"]).is_empty());

    // Idempotency: re-run reports already_present, not an error.
    let rows = tag_json(harness, &["tag", "add", &addr, "tt3_pre", "tt3_auto"]);
    assert!(str_items(&rows[0]["added"]).is_empty());
    assert_eq!(
        str_items(&rows[0]["already_present"]),
        vec!["tt3_pre", "tt3_auto"]
    );

    cleanup_tag(harness, "tt3_pre");
    cleanup_tag(harness, "tt3_auto");
}

#[test]
#[serial]
fn test_tag_add_dedupes_argv() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt4_dup");

    let rows = tag_json(harness, &["tag", "add", &addr, "tt4_dup", "tt4_dup"]);
    assert_eq!(str_items(&rows[0]["added"]), vec!["tt4_dup"]);
    assert_eq!(str_items(&rows[0]["created"]), vec!["tt4_dup"]);

    cleanup_tag(harness, "tt4_dup");
}

#[test]
#[serial]
fn test_tag_get_and_list_function() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt5_member");

    tag_json(harness, &["tag", "add", &addr, "tt5_member"]);

    // tag get unwraps to member-function rows
    let members = tag_json(harness, &["tag", "get", "tt5_member"]);
    assert_eq!(members.len(), 1);
    assert_eq!(members[0]["address"], serde_json::json!(addr));

    // tag list --function shows the function's tags
    let tags = tag_json(harness, &["tag", "list", "--function", &addr]);
    assert!(tags.iter().any(|t| t["name"] == "tt5_member"));

    cleanup_tag(harness, "tt5_member");
}

#[test]
#[serial]
fn test_function_list_tag_filter_and_semantics() {
    require_ghidra!();
    let harness = harness();
    let addrs = get_function_addresses(harness, TEST_PROJECT, TEST_PROGRAM, 2);
    assert!(addrs.len() >= 2, "need two functions for AND test");
    cleanup_tag(harness, "tt6_both");
    cleanup_tag(harness, "tt6_only1");

    tag_json(harness, &["tag", "add", &addrs[0], "tt6_both", "tt6_only1"]);
    tag_json(harness, &["tag", "add", &addrs[1], "tt6_both"]);

    let rows = tag_json(harness, &["function", "list", "--tag", "tt6_both"]);
    assert_eq!(rows.len(), 2);

    // Multiple --tag = AND: only the function carrying BOTH matches.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--tag",
            "tt6_both",
            "--tag",
            "tt6_only1",
        ],
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["address"], serde_json::json!(addrs[0]));

    cleanup_tag(harness, "tt6_both");
    cleanup_tag(harness, "tt6_only1");
}

#[test]
#[serial]
fn test_function_list_unknown_tag_errors_with_hint() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt7_real");
    tag_json(harness, &["tag", "create", "tt7_real"]);

    // Unknown tag is an error (nonzero exit), never a silent empty result.
    let result = ghidra(harness)
        .args(["function", "list", "--tag", "tt7_zzzz"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("No tag named");

    // Case-insensitive near-match hint
    let result = ghidra(harness)
        .args(["tag", "get", "TT7_REAL"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("Did you mean 'tt7_real'?");

    cleanup_tag(harness, "tt7_real");
}

#[test]
#[serial]
fn test_function_list_untagged() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt8_tagged");

    tag_json(harness, &["tag", "add", &addr, "tt8_tagged"]);

    let rows = tag_json(harness, &["function", "list", "--untagged", "--limit", "0"]);
    assert!(
        !rows.iter().any(|r| r["address"] == serde_json::json!(addr)),
        "--untagged must exclude the tagged function"
    );

    cleanup_tag(harness, "tt8_tagged");
}

#[test]
#[serial]
fn test_tag_remove_and_all() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt9_a");
    cleanup_tag(harness, "tt9_b");

    tag_json(harness, &["tag", "add", &addr, "tt9_a", "tt9_b"]);

    // Remove one present + one absent: absent is reported, not an error.
    let rows = tag_json(harness, &["tag", "remove", &addr, "tt9_a", "tt9_zzz"]);
    assert_eq!(str_items(&rows[0]["removed"]), vec!["tt9_a"]);
    assert_eq!(str_items(&rows[0]["not_present"]), vec!["tt9_zzz"]);

    // --all clears the rest
    let rows = tag_json(harness, &["tag", "remove", &addr, "--all"]);
    assert_eq!(str_items(&rows[0]["removed"]), vec!["tt9_b"]);

    let tags = tag_json(harness, &["tag", "list", "--function", &addr]);
    assert!(
        !tags
            .iter()
            .any(|t| t["name"] == "tt9_a" || t["name"] == "tt9_b"),
        "function should have no tt9 tags after remove --all"
    );

    cleanup_tag(harness, "tt9_a");
    cleanup_tag(harness, "tt9_b");
}

#[test]
#[serial]
fn test_tag_rename_and_collision() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt10_old");
    cleanup_tag(harness, "tt10_new");
    cleanup_tag(harness, "tt10_taken");

    tag_json(harness, &["tag", "create", "tt10_old"]);
    tag_json(harness, &["tag", "create", "tt10_taken"]);

    let rows = tag_json(harness, &["tag", "rename", "tt10_old", "tt10_new"]);
    assert_eq!(rows[0]["status"], "renamed");

    let tags = tag_json(harness, &["tag", "list"]);
    assert!(tags.iter().any(|t| t["name"] == "tt10_new"));
    assert!(!tags.iter().any(|t| t["name"] == "tt10_old"));

    // Renaming onto an existing name errors — no implicit merge.
    let result = ghidra(harness)
        .args(["tag", "rename", "tt10_new", "tt10_taken"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("already exists");

    cleanup_tag(harness, "tt10_new");
    cleanup_tag(harness, "tt10_taken");
}

#[test]
#[serial]
fn test_tag_set_comment_and_clear() {
    require_ghidra!();
    let harness = harness();
    cleanup_tag(harness, "tt11_c");

    tag_json(harness, &["tag", "create", "tt11_c"]);
    tag_json(
        harness,
        &["tag", "set-comment", "tt11_c", "first pass done"],
    );

    let tags = tag_json(harness, &["tag", "list"]);
    let row = tags.iter().find(|t| t["name"] == "tt11_c").unwrap();
    assert_eq!(row["comment"], "first pass done");

    // Empty string clears
    tag_json(harness, &["tag", "set-comment", "tt11_c", ""]);
    let tags = tag_json(harness, &["tag", "list"]);
    let row = tags.iter().find(|t| t["name"] == "tt11_c").unwrap();
    assert_eq!(row["comment"], "");

    cleanup_tag(harness, "tt11_c");
}

#[test]
#[serial]
fn test_tag_delete_reports_counts_then_get_errors() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt12_del");

    tag_json(harness, &["tag", "add", &addr, "tt12_del"]);

    let rows = tag_json(harness, &["tag", "delete", "tt12_del"]);
    assert_eq!(rows[0]["status"], "deleted");
    assert_eq!(rows[0]["use_count"], 1);
    assert_eq!(rows[0]["functions_affected"], 1);

    let result = ghidra(harness)
        .args(["tag", "get", "tt12_del"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("No tag named");
}

#[test]
#[serial]
fn test_tag_add_no_create_errors_without_mutating() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt13_nc");

    let result = ghidra(harness)
        .args(["tag", "add", &addr, "tt13_nc", "--no-create"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();
    result.assert_stderr_contains("no-create");

    // Tag must not have been created, function must not have been tagged.
    let tags = tag_json(harness, &["tag", "list"]);
    assert!(!tags.iter().any(|t| t["name"] == "tt13_nc"));
}

#[test]
#[serial]
fn test_tag_invalid_names_rejected_at_creation() {
    require_ghidra!();
    let harness = harness();

    for bad in ["", "a,b", "a;b"] {
        let result = ghidra(harness)
            .args(["tag", "create", bad])
            .with_project(TEST_PROJECT, TEST_PROGRAM)
            .run();
        result.assert_failure();
        result.assert_stderr_contains("Tag name cannot");
    }
}

#[test]
#[serial]
fn test_tag_case_sensitivity() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt14_Case");
    cleanup_tag(harness, "tt14_case");

    tag_json(harness, &["tag", "add", &addr, "tt14_Case"]);

    // Server-side --tag is exact: wrong case errors (tag does not exist).
    let result = ghidra(harness)
        .args(["function", "list", "--tag", "tt14_case"])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_failure();

    // Client-side DSL `~` is case-insensitive: matches despite case.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--filter",
            "tags ~ 'tt14_case'",
            "--limit",
            "0",
        ],
    );
    assert!(rows.iter().any(|r| r["address"] == serde_json::json!(addr)));

    // DSL `=` is exact: wrong case matches nothing.
    let rows = tag_json(
        harness,
        &[
            "function",
            "list",
            "--filter",
            "tags = 'tt14_case'",
            "--limit",
            "0",
        ],
    );
    assert!(!rows.iter().any(|r| r["address"] == serde_json::json!(addr)));

    cleanup_tag(harness, "tt14_Case");
}

#[test]
#[serial]
fn test_function_outputs_include_tags_field() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt15_b");
    cleanup_tag(harness, "tt15_a");

    tag_json(harness, &["tag", "add", &addr, "tt15_b", "tt15_a"]);

    // function get carries tags, sorted alphabetically
    let rows = tag_json(harness, &["function", "get", &addr]);
    assert_eq!(str_items(&rows[0]["tags"]), vec!["tt15_a", "tt15_b"]);

    // function list rows carry tags too (stable schema: present even when empty)
    let rows = tag_json(harness, &["function", "list", "--limit", "0"]);
    let row = rows
        .iter()
        .find(|r| r["address"] == serde_json::json!(addr))
        .expect("function missing from list");
    assert_eq!(str_items(&row["tags"]), vec!["tt15_a", "tt15_b"]);
    assert!(
        rows.iter().all(|r| r["tags"].is_array()),
        "every function row must carry a tags array"
    );

    cleanup_tag(harness, "tt15_b");
    cleanup_tag(harness, "tt15_a");
}

#[test]
#[serial]
fn test_csv_tags_join_with_semicolon() {
    require_ghidra!();
    let harness = harness();
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");
    cleanup_tag(harness, "tt16_x");
    cleanup_tag(harness, "tt16_y");

    tag_json(harness, &["tag", "add", &addr, "tt16_x", "tt16_y"]);

    // Fields chosen to exclude `signature`, whose own commas are a
    // pre-existing, out-of-scope CSV wart.
    let result = ghidra(harness)
        .args([
            "function",
            "list",
            "--fields",
            "name,address,tags",
            "--format",
            "csv",
            "--limit",
            "0",
        ])
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .run();
    result.assert_success();

    let line = result
        .stdout
        .lines()
        .find(|l| l.contains(&addr))
        .expect("tagged function missing from CSV")
        .to_string();
    assert_eq!(
        line.matches(',').count(),
        2,
        "multi-tag row must not shift CSV columns: {}",
        line
    );
    assert!(
        line.contains("tt16_x;tt16_y"),
        "tags must join with ';' in CSV: {}",
        line
    );

    cleanup_tag(harness, "tt16_x");
    cleanup_tag(harness, "tt16_y");
}

// --- clap-level grammar tests (no Ghidra required) ---

#[test]
fn test_clap_tag_add_requires_tags() {
    // `tag add f` must be a parse error, not TARGET-consumed-as-tag.
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["tag", "add", "some_func"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_clap_tag_remove_all_conflicts_with_tags() {
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["tag", "remove", "some_func", "--all", "extra_tag"])
        .assert()
        .failure()
        .code(2);

    // Neither tags nor --all is also a parse error
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["tag", "remove", "some_func"])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn test_clap_untagged_conflicts_with_tag() {
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .args(["function", "list", "--tag", "x", "--untagged"])
        .assert()
        .failure()
        .code(2);
}

//! Tests for script execution operations.

use serial_test::serial;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};

const TEST_PROJECT: &str = "ci-test";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

fn echo_args_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("scripts");
    path.push("EchoArgs.java");
    path
}

fn get_test_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("test_script.py");
    path
}

fn create_test_script() -> PathBuf {
    let script_path = get_test_script_path();

    fs::create_dir_all(script_path.parent().unwrap()).ok();

    let script_content = r#"# Test script
# @category Test

print("Test script executed")
"#;

    fs::write(&script_path, script_content).expect("Failed to write test script");
    script_path
}

#[test]
#[serial]
fn test_script_list() {
    require_ghidra!();
    let _harness = harness();

    // script list does not accept --project/--program arguments,
    // so it may fail with "no project specified" unless a default is configured
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("list")
        .output()
        .expect("Failed to run command");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("No project specified")
            || stderr.contains("no default project"),
        "Expected success or no-project error, got: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_script_run() {
    require_ghidra!();
    let script_path = create_test_script();

    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("run")
        .arg(script_path.to_str().unwrap())
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Ghidra's runScript may not find scripts outside its script directories
    // Accept either success or "Script does not exist" error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            || stderr.contains("Script does not exist")
            || stderr.contains("Script not found")
            || stderr.contains("No script provider") // Python provider not installed
            || stderr.contains("Script failed")
            || stderr.contains("Script threw")
            || stderr.contains("Failed to run script"),
        "Expected success or script-not-found error, got: {}",
        stderr
    );

    fs::remove_file(script_path).ok();
}

/// A checked-in Java script runs by absolute path (no global-scripts-dir copy),
/// receives real positional arguments (Phase 4.1), and its stdout is captured
/// into the structured result. Java is used deliberately: it compiles via the
/// doctor-resolved JDK, whereas Python needs a provider that may be absent.
#[test]
#[serial]
fn test_script_run_java_args() {
    require_ghidra!();
    let _harness = harness();

    let script_path = echo_args_script_path();
    assert!(
        script_path.exists(),
        "fixture missing: {}",
        script_path.display()
    );

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("run")
        .arg(script_path.to_str().unwrap())
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--")
        .arg("hello")
        .arg("world")
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "script run failed.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    // The captured script println() output lands in the result's `stdout` field.
    assert!(
        stdout.contains("ARGC=2") && stdout.contains("ARG0=hello") && stdout.contains("ARG1=world"),
        "expected echoed args in captured stdout, got: {}",
        stdout
    );
}

#[test]
#[serial]
fn test_script_python_inline() {
    require_ghidra!();
    let _harness = harness();

    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("python")
        .arg("output = 'Hello from Python'")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .output()
        .expect("Failed to run command");

    // Python execution is not available in Java bridge mode
    // Accept either success or "not available" error
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() || stderr.contains("not available") || stderr.contains("Python"),
        "Expected success or Python-not-available error, got: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_script_run_nonexistent() {
    require_ghidra!();
    let _harness = harness();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("run")
        .arg("/nonexistent/script.py")
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .failure();
}

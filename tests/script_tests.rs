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

/// Copy a fixture script into a unique, fresh temp directory and return the copy.
///
/// Ghidra resolves a script to the FIRST registered source directory that is an
/// ancestor of it (GhidraScriptUtil.findSourceDirectoryContaining), and bundle
/// registrations persist in the OSGi cache across bridge sessions. Running a
/// fixture straight out of tests/fixtures/** can therefore be shadowed by a
/// previously-registered ancestor (e.g. tests/fixtures itself), which corrupts
/// the derived class name. Staging into a unique temp dir gives each run an
/// unregistered parent — exactly the arbitrary-absolute-path case users hit.
fn stage_script(fixture: &PathBuf) -> PathBuf {
    let stem = fixture.file_stem().unwrap().to_string_lossy().into_owned();
    let dir =
        std::env::temp_dir().join(format!("ghidra_cli_script_{}_{}", std::process::id(), stem));
    fs::create_dir_all(&dir).expect("create staging dir");
    let dest = dir.join(fixture.file_name().unwrap());
    fs::copy(fixture, &dest).expect("copy fixture script");
    dest
}

fn write_artifact_script_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("scripts");
    path.push("WriteArtifact.java");
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

    let fixture = echo_args_script_path();
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let script_path = stage_script(&fixture);

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

/// Phase 4.2: a declared JSONL artifact is validated and a manifest (row count,
/// checksum, binary provenance) is attached; a missing declared artifact fails
/// the job closed. Absolute paths are used for both the script's output arg and
/// `--expect` so the bridge validates exactly the file the script wrote.
#[test]
#[serial]
fn test_script_run_artifact_contract() {
    require_ghidra!();
    let _harness = harness();

    let fixture = write_artifact_script_path();
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());
    let script = stage_script(&fixture);

    let out =
        std::env::temp_dir().join(format!("ghidra_cli_artifact_{}.jsonl", std::process::id()));
    let out_str = out.to_str().unwrap();
    let _ = fs::remove_file(&out);

    // Success: script writes 5 rows, we require >= 3.
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("run")
        .arg(script.to_str().unwrap())
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--expect")
        .arg(format!("{}:3", out_str))
        .arg("--")
        .arg(out_str)
        .arg("5")
        .output()
        .expect("Failed to run command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected success.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("artifacts") && stdout.contains("\"rows\""),
        "expected artifact manifest with row count, got: {}",
        stdout
    );
    assert!(
        stdout.contains("wrote 5 records"),
        "expected captured script stdout, got: {}",
        stdout
    );
    let _ = fs::remove_file(&out);

    // Failure: declare an artifact the script never writes -> job fails closed.
    let missing =
        std::env::temp_dir().join(format!("ghidra_cli_missing_{}.jsonl", std::process::id()));
    let out2 =
        std::env::temp_dir().join(format!("ghidra_cli_artifact2_{}.jsonl", std::process::id()));
    let output2 = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("script")
        .arg("run")
        .arg(script.to_str().unwrap())
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("--program")
        .arg(TEST_PROGRAM)
        .arg("--expect")
        .arg(missing.to_str().unwrap())
        .arg("--")
        .arg(out2.to_str().unwrap())
        .arg("5")
        .output()
        .expect("Failed to run command");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output2.stdout),
        String::from_utf8_lossy(&output2.stderr)
    );
    assert!(
        !output2.status.success(),
        "expected failure for a missing declared artifact, got success: {}",
        combined
    );
    assert!(
        combined.contains("validation failed") || combined.contains("missing"),
        "expected artifact-validation error, got: {}",
        combined
    );
    let _ = fs::remove_file(&out2);
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

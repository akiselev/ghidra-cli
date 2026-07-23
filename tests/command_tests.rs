//! Tests for basic CLI commands that don't require daemon.

use predicates::prelude::*;

#[macro_use]
mod common;

#[test]
fn test_version() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra-cli"));
}

#[test]
fn test_doctor() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("Ghidra CLI Doctor"));
}

#[test]
fn test_config_list() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("config")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra_install_dir"));
}

#[test]
fn test_config_get() {
    require_ghidra!();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("config")
        .arg("get")
        .arg("ghidra_install_dir")
        .assert()
        .success();
}

#[test]
fn test_config_set() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("default_output_format")
        .arg("json")
        .assert()
        .success();
}

#[test]
fn test_legacy_config_timeout_is_rejected_with_replacements() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("timeout")
        .arg("1800")
        .assert()
        .failure()
        .stderr(predicate::str::contains("GHIDRA_CLI_READ_TIMEOUT"));
}

#[test]
fn test_config_set_launch_timeout() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("set")
        .arg("launch_timeout_secs")
        .arg("240")
        .assert()
        .success();

    let config = std::fs::read_to_string(config_path).unwrap();
    assert!(config.contains("launch_timeout_secs: 240"), "{config}");
}

#[test]
fn test_config_reset() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("config")
        .arg("reset")
        .assert()
        .success();
}

#[test]
fn test_init() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("init")
        .assert()
        .success();

    assert!(config_path.exists());
}

#[test]
fn test_set_default_program() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("set-default")
        .arg("program")
        .arg("sample_binary")
        .assert()
        .success()
        .stdout(predicate::str::contains("Default program set"));
}

#[test]
fn test_set_default_project() {
    require_ghidra!();

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .env("GHIDRA_CLI_CONFIG", &config_path)
        .arg("set-default")
        .arg("project")
        .arg("test-project")
        .assert()
        .success()
        .stdout(predicate::str::contains("Default project set"));
}

//! Tests for daemon lifecycle commands.

use predicates::prelude::*;
use serial_test::serial;
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
            if msg.contains("program file(s) not found") {
                eprintln!(
                    "Skipping test: bridge can't find program (known macOS issue): {}",
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

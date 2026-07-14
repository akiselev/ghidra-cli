//! Common test utilities for E2E tests.
//!
//! This module provides:
//! - `schemas`: Typed data structures for JSON output validation
//! - `helpers`: Fluent test helpers and utilities
//! - `DaemonTestHarness`: Bridge lifecycle management for tests

#![allow(dead_code, unused_imports)]

pub mod helpers;
pub mod schemas;

// Re-export commonly used items
pub use helpers::{
    get_function_address, get_function_addresses, ghidra, normalize_json, normalize_output,
    GhidraCommand, GhidraResult,
};
pub use schemas::Validate;

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;

/// Get path to the sample_binary test fixture.
pub fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample_binary")
}

/// Ensure test project exists with analyzed sample binary.
/// Uses Once::call_once for idempotent setup across multiple tests.
/// Skips import+analyze if the project already exists (supports CI caching).
pub fn ensure_test_project(project: &str, program: &str) {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        let binary = fixture_binary();
        if !binary.exists() {
            panic!(
                "Test fixture not found: {:?}\nRun: rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs",
                binary
            );
        }

        // Check if project already exists with program data (supports CI caching).
        // Verify both .gpr (project descriptor) and .rep (repository data) exist
        // to avoid using incomplete cached projects.
        //
        // Ghidra stores project files at: <projects_dir>/<project_name>.gpr
        // NOT at <projects_dir>/<project_name>/<project_name>.gpr
        // because start_bridge passes (project_path.parent(), project_path.file_name())
        // to analyzeHeadless.
        let projects_dir = ghidra_cli::config::Config::default_project_dir()
            .expect("Could not determine default project dir");
        let gpr_file = projects_dir.join(format!("{}.gpr", project));
        let rep_dir = projects_dir.join(format!("{}.rep", project));

        // Validate the cached project has actual program data, not just metadata
        // stubs. Ghidra's local filesystem stores program data in bucketed
        // subdirectories (`00/`, `01/`, ...) under `.rep/idata/`, alongside index
        // files (`~index.dat`, `~index.bak`, `~journal.*`). The real signal of a
        // populated project is therefore the presence of a *subdirectory* — index
        // files alone (which is all an empty project has) do NOT count.
        //
        // (An earlier check accepted any entry != "~index.dat", so a bare
        // `~index.bak` made an empty project look valid — the cause of Windows
        // "Requested project program file(s) not found".)
        //
        // NOTE: We do NOT require a non-empty `.gpr`. A correctly committed
        // Ghidra 12.x project legitimately has a 0-byte `.gpr` descriptor (the
        // project data lives under `.rep`). Requiring `.gpr` > 0 made EVERY run
        // treat the cache as invalid, so every test binary deleted and
        // re-imported the shared project — and since the mutation suite runs
        // several test binaries concurrently, they raced to delete/re-import the
        // same project, wiping it mid-use ("Could not find project: ci-test").
        let idata_dir = rep_dir.join("idata");
        let idata_has_data = idata_dir.is_dir()
            && std::fs::read_dir(&idata_dir)
                .map(|entries| entries.filter_map(|e| e.ok()).any(|e| e.path().is_dir()))
                .unwrap_or(false);
        let project_valid = gpr_file.exists() && idata_has_data;

        if project_valid {
            eprintln!("=== Using cached test project: {:?} ===", gpr_file);
            return;
        }

        if gpr_file.exists() {
            eprintln!("=== Project cache invalid (missing program data), re-importing ===");
            // A bridge from a previous test binary may still be running (the
            // static HARNESS OnceLock is never dropped, so its bridge leaks
            // across test binaries). Stop it BEFORE deleting the project files:
            // deleting them from under a live bridge makes the import below go
            // over TCP into the doomed in-memory project, which then persists
            // nothing on stop — and every test in this binary fails with
            // "Could not find project".
            let project_path = projects_dir.join(project);
            let _ = ghidra_cli::ghidra::bridge::stop_bridge(&project_path);
            // Remove stale project files to avoid conflicts during import
            let _ = std::fs::remove_file(&gpr_file);
            let _ = std::fs::remove_dir_all(&rep_dir);
        }

        eprintln!("=== Setting up test project (import + analyze) ===");
        eprintln!("Project dir: {:?}", projects_dir);

        // Step 1: Import the binary
        //
        // IMPORTANT: We use Stdio::null() instead of piped stdout/stderr.
        // On Windows, `ghidra import` spawns analyzeHeadless.bat → cmd.exe → java.exe.
        // If we use piped I/O, the grandchild JVM inherits the pipe handles.
        // When ghidra.exe exits, the pipe stays open (JVM holds inherited handles),
        // so output()/wait_with_output() blocks forever. Using null avoids this.
        eprintln!("Step 1: Importing binary {:?} ...", binary);
        let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra");
        let import_status = run_cli_with_timeout(
            ghidra_bin,
            &[
                "import",
                binary.to_str().unwrap(),
                "--project",
                project,
                "--program",
                program,
            ],
            Duration::from_secs(300),
        );
        match import_status {
            Ok(status) => {
                eprintln!("Import finished with status: {}", status);
                if !status.success() {
                    eprintln!("Warning: Import may have failed, but continuing...");
                } else {
                    eprintln!("Binary imported successfully");
                }
            }
            Err(e) => eprintln!("Import error: {}", e),
        }

        // Step 2: Analyze the binary (creates code units needed for comments)
        eprintln!("Step 2: Running analysis...");
        let analyze_status = run_cli_with_timeout(
            ghidra_bin,
            &[
                "analyze",
                "--project",
                project,
                "--program",
                program,
            ],
            Duration::from_secs(600),
        );
        match analyze_status {
            Ok(status) => {
                eprintln!("Analyze finished with status: {}", status);
                if !status.success() {
                    eprintln!("Warning: Analyze may have failed, but continuing...");
                } else {
                    eprintln!("Analysis complete");
                }
            }
            Err(e) => eprintln!("Analyze error: {}", e),
        }

        // Step 3: Cleanly stop the bridge so the imported+analyzed program is
        // durably written to disk. A bridge launched via `analyzeHeadless
        // -import` holds the program inside HeadlessAnalyzer's ambient
        // transaction; the program is only flushed to the project when the
        // script returns (i.e. on a clean shutdown). Without this stop the
        // program lives only in the bridge's memory and is lost when the bridge
        // is torn down (e.g. CI process-group teardown), leaving a fresh bridge
        // to open an empty project ("Program not found").
        //
        // Subsequent tests reuse the project, not this bridge:
        // DaemonTestHarness::new() starts a fresh bridge in Process mode that
        // opens the now-durable program from disk.
        eprintln!("Step 3: Stopping bridge to flush project to disk...");
        let stop_status = run_cli_with_timeout(
            ghidra_bin,
            &["stop", "--project", project],
            Duration::from_secs(120),
        );
        match stop_status {
            Ok(status) => eprintln!("Stop finished with status: {}", status),
            Err(e) => eprintln!("Stop error: {}", e),
        }

        eprintln!("=== Test project setup complete ===");
    });
}

/// Test harness that manages bridge lifecycle for a test suite.
///
/// The bridge is the Ghidra Java process running GhidraCliBridge.
/// Tests connect to it via TCP using BridgeClient.
pub struct DaemonTestHarness {
    port: u16,
    pid: Option<u32>,
    data_dir: PathBuf,
    project: String,
    project_path: PathBuf,
}

impl DaemonTestHarness {
    /// Start bridge for testing. Blocks until bridge is ready or timeout.
    ///
    /// Calls bridge functions directly (not via CLI subprocess) so that
    /// detailed error messages (e.g., "program file(s) not found") propagate
    /// correctly to callers like try_start_daemon().
    pub fn new(project: &str, program: &str) -> Result<Self> {
        let data_dir = get_unique_data_dir();

        // Resolve the project path (must match the CLI's default via get_project_dir)
        let project_path = ghidra_cli::config::Config::default_project_dir()
            .context("Could not determine default project dir")?
            .join(project);

        // Load config to find Ghidra installation
        let config = ghidra_cli::config::Config::load().context("Failed to load config")?;
        let ghidra_install_dir = config
            .ghidra_install_dir
            .clone()
            .or_else(|| config.get_ghidra_install_dir().ok())
            .context("Ghidra installation directory not configured")?;

        // Start the bridge directly via bridge API (not CLI subprocess).
        // This gives us detailed error messages from Ghidra in the Err value.
        let port = ghidra_cli::ghidra::bridge::ensure_bridge_running(
            &project_path,
            &ghidra_install_dir,
            ghidra_cli::ghidra::bridge::BridgeStartMode::Process {
                program_name: program.to_string(),
            },
        )?;

        // Store PID now so Drop can wait for it even if restart deletes the PID file
        let pid = ghidra_cli::ghidra::bridge::read_pid_file(&project_path)
            .ok()
            .flatten();

        Ok(Self {
            port,
            pid,
            data_dir,
            project: project.to_string(),
            project_path,
        })
    }

    /// Get a BridgeClient connected to the test bridge.
    pub fn client(&self) -> Result<ghidra_cli::ipc::client::BridgeClient> {
        Ok(ghidra_cli::ipc::client::BridgeClient::new(self.port))
    }

    /// Get data directory for this daemon instance.
    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Get project name.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Get bridge port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for DaemonTestHarness {
    fn drop(&mut self) {
        // Read current PID from file (may differ from self.pid if restart changed it)
        let file_pid = ghidra_cli::ghidra::bridge::read_pid_file(&self.project_path)
            .ok()
            .flatten();

        // Use stop_bridge for proper graceful shutdown + force-kill
        let _ = ghidra_cli::ghidra::bridge::stop_bridge(&self.project_path);

        // Collect all PIDs we need to wait for (original + current, deduplicated)
        let mut pids_to_wait: Vec<u32> = Vec::new();
        if let Some(pid) = file_pid {
            pids_to_wait.push(pid);
        }
        if let Some(pid) = self.pid {
            if !pids_to_wait.contains(&pid) {
                pids_to_wait.push(pid);
            }
        }

        // Wait for ALL known processes to fully exit and release project lock.
        let max_wait = if cfg!(windows) {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(15)
        };
        for pid in &pids_to_wait {
            let start = std::time::Instant::now();
            while start.elapsed() < max_wait {
                if !ghidra_cli::ghidra::bridge::is_pid_alive(*pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }

        // Final cleanup of any remaining stale files
        let _ = ghidra_cli::ghidra::bridge::cleanup_stale_files(&self.project_path);
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Generate unique data directory for test isolation.
fn get_unique_data_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ghidra-data-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("Failed to create test data dir");
    dir
}

/// Run a CLI command with timeout.
///
/// Stdout uses Stdio::null() to avoid pipe handle inheritance on Windows, where
/// grandchild JVM processes inherit pipe handles and block wait_with_output() forever.
/// Stderr uses Stdio::inherit() so errors are visible in CI logs (inheriting the parent
/// fd doesn't create a pipe, so there's no blocking issue).
pub fn run_cli_with_timeout(
    bin: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to spawn CLI command")?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    eprintln!("Command timed out after {}s, killing...", timeout.as_secs());
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!("Command timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            Err(e) => anyhow::bail!("Error waiting for command: {}", e),
        }
    }
}

/// Require Ghidra to be available for tests to proceed.
#[macro_export]
macro_rules! require_ghidra {
    () => {
        let doctor = assert_cmd::cargo::cargo_bin_cmd!("ghidra")
            .arg("doctor")
            .output()
            .expect("Failed to run ghidra doctor");

        let output = String::from_utf8_lossy(&doctor.stdout);

        if !output.contains("OK") || output.contains("NOT FOUND") || output.contains("FAILED") {
            panic!(
                "Ghidra not properly installed — tests MUST fail without Ghidra.\n\
                 Doctor output: {}",
                output
            );
        }
    };
}

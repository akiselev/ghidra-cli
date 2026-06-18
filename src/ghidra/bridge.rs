//! Ghidra Bridge - manages a persistent Ghidra Java bridge process.
//!
//! The bridge runs a GhidraCliBridge.java script via `analyzeHeadless` that
//! starts a TCP socket server. The CLI connects directly to this server
//! to execute commands. No intermediate daemon process is needed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::ipc::client::BridgeClient;

/// How to start the bridge - import a new binary or open an existing program.
pub enum BridgeStartMode {
    /// Import a binary file into the project, then start bridge
    Import { binary_path: String },
    /// Open an existing program in the project
    Process { program_name: String },
    /// Open the project without loading a specific program
    Project,
}

/// Embedded Java bridge script
const JAVA_BRIDGE_SCRIPT: &str = include_str!("scripts/GhidraCliBridge.java");

/// Get the data directory for bridge port/PID files.
pub fn get_data_dir() -> Result<PathBuf> {
    let dir = dirs::data_local_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine data directory"))?
        .join("ghidra-cli");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Compute MD5 hash of project path for file naming.
fn project_hash(project_path: &Path) -> String {
    format!(
        "{:x}",
        md5::compute(project_path.to_string_lossy().as_bytes())
    )
}

/// Get the port file path for a project.
pub fn port_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.port", hash)))
}

/// Get the PID file path for a project.
pub fn pid_file_path(project_path: &Path) -> Result<PathBuf> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    Ok(data_dir.join(format!("bridge-{}.pid", hash)))
}

/// Read the port from the port file.
pub fn read_port_file(project_path: &Path) -> Result<Option<u16>> {
    let path = port_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let port: u16 = content
        .trim()
        .parse()
        .context("Invalid port in port file")?;
    Ok(Some(port))
}

/// Read the PID from the PID file.
pub fn read_pid_file(project_path: &Path) -> Result<Option<u32>> {
    let path = pid_file_path(project_path)?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let pid: u32 = content.trim().parse().context("Invalid PID in PID file")?;
    Ok(Some(pid))
}

/// Check if a process with the given PID is alive.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
}

/// Clean up stale port and PID files.
pub fn cleanup_stale_files(project_path: &Path) -> Result<()> {
    let port_path = port_file_path(project_path)?;
    let pid_path = pid_file_path(project_path)?;
    if port_path.exists() {
        std::fs::remove_file(&port_path).ok();
    }
    if pid_path.exists() {
        std::fs::remove_file(&pid_path).ok();
    }

    // Remove Ghidra project lock files left behind after force-kill.
    // Ghidra creates {project_name}.lock and {project_name}.lock~ as siblings
    // of the project directory. If the JVM is killed, these aren't cleaned up
    // and the next analyzeHeadless invocation may refuse to open the project.
    if let Some(project_name) = project_path.file_name() {
        if let Some(parent) = project_path.parent() {
            let lock_name = format!("{}.lock", project_name.to_string_lossy());
            let lock_path = parent.join(&lock_name);
            let lock_tilde = parent.join(format!("{}~", lock_name));
            if lock_path.exists() {
                debug!("Removing stale Ghidra lock: {:?}", lock_path);
                std::fs::remove_file(&lock_path).ok();
            }
            if lock_tilde.exists() {
                debug!("Removing stale Ghidra lock: {:?}", lock_tilde);
                std::fs::remove_file(&lock_tilde).ok();
            }
        }
    }

    Ok(())
}

/// RAII guard that removes the startup lock file on drop.
struct StartupLockGuard {
    path: PathBuf,
}

impl Drop for StartupLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Acquire a per-project startup lock so concurrent callers don't each spawn
/// their own analyzeHeadless (which would cause "Unable to lock project!").
///
/// The lock file contains the holder's PID so stale locks (from crashed
/// processes) are detected and cleaned up automatically.
///
/// Blocks until the lock is acquired or the 60-second timeout expires.
fn acquire_startup_lock(project_path: &Path) -> Result<StartupLockGuard> {
    let data_dir = get_data_dir()?;
    let hash = project_hash(project_path);
    let lock_path = data_dir.join(format!("bridge-{}.starting", hash));
    let pid = std::process::id().to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);

    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut f) => {
                let _ = f.write_all(pid.as_bytes());
                debug!("Acquired startup lock: {:?}", lock_path);
                return Ok(StartupLockGuard { path: lock_path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // If the holder process is dead, remove the stale lock and retry.
                if let Ok(content) = std::fs::read_to_string(&lock_path) {
                    if let Ok(holder_pid) = content.trim().parse::<u32>() {
                        if !is_pid_alive(holder_pid) {
                            debug!("Removing stale startup lock from dead PID {}", holder_pid);
                            let _ = std::fs::remove_file(&lock_path);
                            continue;
                        }
                    }
                }
                if std::time::Instant::now() > deadline {
                    anyhow::bail!(
                        "Timed out waiting for bridge startup lock \
                         (another process may be starting the bridge)"
                    );
                }
                debug!("Waiting for startup lock...");
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Check if a bridge is running for the given project.
///
/// Verifies: port file exists, PID is alive, TCP connect succeeds.
/// Returns `Some(port)` if running, `None` otherwise. Callers use the returned port
/// directly, avoiding a separate read_port_file call (TOCTOU elimination).
pub fn is_bridge_running(project_path: &Path) -> Option<u16> {
    let port = match read_port_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    let pid = match read_pid_file(project_path) {
        Ok(Some(p)) => p,
        _ => return None,
    };

    if !is_pid_alive(pid) {
        return None;
    }

    // Verify TCP connect (with timeout to avoid long hangs on Windows)
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().ok()?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map(|_| Some(port))
        .unwrap_or(None)
}

/// Ensure a bridge is running for the given project.
/// Returns the port number to connect to.
///
/// Safe for concurrent callers: uses a per-project startup lock so that
/// only one process spawns analyzeHeadless. The others wait and reuse the
/// bridge that the winner started.
pub fn ensure_bridge_running(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    // Fast path (no lock): if the bridge is clearly running, return immediately.
    if let Some(port) = is_bridge_running(project_path) {
        info!("Bridge already running on port {}", port);
        return Ok(port);
    }

    // Slow path: acquire the per-project startup lock so that concurrent
    // callers don't each launch their own analyzeHeadless (which would fail
    // with "Unable to lock project!" because Ghidra uses an exclusive lock).
    let _lock = acquire_startup_lock(project_path)?;

    // Re-check under the lock: another process may have started the bridge
    // while we were waiting.
    if let Some(port) = is_bridge_running(project_path) {
        info!("Bridge already running on port {} (detected after lock)", port);
        return Ok(port);
    }

    // Clean up any stale port/pid/lock files before starting fresh.
    cleanup_stale_files(project_path)?;
    start_bridge(project_path, ghidra_install_dir, mode)
}

/// Start a new bridge process.
/// Returns the port number once the bridge is ready.
pub fn start_bridge(
    project_path: &Path,
    ghidra_install_dir: &Path,
    mode: BridgeStartMode,
) -> Result<u16> {
    info!("Starting Ghidra bridge...");

    // Write the Java bridge script to disk
    let scripts_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("ghidra-cli")
        .join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;
    let java_script_path = scripts_dir.join("GhidraCliBridge.java");
    std::fs::write(&java_script_path, JAVA_BRIDGE_SCRIPT)?;

    // Find analyzeHeadless
    let headless_script = find_headless_script(ghidra_install_dir)?;

    // Compute port file path
    let port_file = port_file_path(project_path)?;

    // Build command
    let mut cmd = Command::new(&headless_script);

    // analyzeHeadless expects: <parent_directory> <project_name>
    let ghidra_project_dir = project_path.parent().unwrap_or(project_path);
    let ghidra_project_name = project_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    cmd.arg(ghidra_project_dir).arg(&ghidra_project_name);

    // Add mode-specific args
    match &mode {
        BridgeStartMode::Import { binary_path } => {
            cmd.arg("-import").arg(binary_path);
        }
        BridgeStartMode::Process { program_name } => {
            cmd.arg("-process").arg(program_name).arg("-noanalysis");
        }
        BridgeStartMode::Project => {
            cmd.arg("-process").arg("-noanalysis");
        }
    }

    // Add Java bridge script args
    cmd.arg("-scriptPath")
        .arg(scripts_dir.to_str().unwrap())
        .arg("-postScript")
        .arg("GhidraCliBridge.java")
        .arg(port_file.to_str().unwrap());

    // Select a full JDK for Ghidra. Ghidra compiles the bridge script at runtime
    // via OSGi and needs javac/jdk.compiler, which a JRE lacks. Setting JAVA_HOME
    // on the child overrides Ghidra's PATH-based auto-pick (honored by Ghidra's
    // LaunchSupport on all platforms). If we can't find a JDK, proceed and let
    // Ghidra try — the readiness failure path surfaces an actionable hint.
    let explicit_java = crate::config::Config::load().ok().and_then(|c| c.get_java_home());
    match super::java::resolve_for_ghidra(ghidra_install_dir, explicit_java) {
        Ok(jdk) => {
            info!(
                "Using JDK {} at {} ({})",
                jdk.major,
                jdk.home.display(),
                jdk.source
            );
            cmd.env("JAVA_HOME", &jdk.home);
        }
        Err(e) => {
            warn!("No suitable JDK auto-selected; letting Ghidra choose. {}", e);
        }
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    info!("Ghidra command: {:?}", cmd);

    // Spawn the process
    let mut child = cmd.spawn().context("Failed to spawn Ghidra headless")?;
    info!("Ghidra process started with PID: {:?}", child.id());

    // Write PID file immediately so orphan cleanup is possible if Java crashes
    // before the ready signal (Java overwrites this once it binds the ServerSocket)
    write_pid_file(project_path, child.id()).ok();

    // Spawn a thread to capture stderr
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut stderr_output = Vec::new();
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra stderr] {}", line);
            stderr_output.push(line);
        }
        stderr_output
    });

    // Wait for bridge to become ready.
    //
    // Two mechanisms run in parallel:
    // 1. Stdout reader thread - watches for the JSON ready signal (fast path)
    // 2. Port file poller - polls port file + TCP ping as fallback
    //
    // On Windows, stdout piping through analyzeHeadless.bat → cmd.exe → java.exe
    // can fail due to buffering, so the port file fallback is essential.
    let stdout = child.stdout.take().expect("stdout should be piped");
    let (stdout_tx, stdout_rx) = std::sync::mpsc::channel();
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut last_error = String::new();
        let mut stdout_lines = Vec::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            info!("[Ghidra stdout] {}", line);
            stdout_lines.push(line.clone());

            if line.contains("ERROR") || line.contains("Exception") || line.contains("SEVERE") {
                last_error = line.clone();
            }

            if line.contains("---GHIDRA_CLI_START---") {
                continue;
            }
            if line.contains("\"status\"") && line.contains("\"ready\"") {
                info!("Bridge is ready (stdout signal)");
                let _ = stdout_tx.send(true);
                return (true, last_error, stdout_lines);
            }
            if line.contains("---GHIDRA_CLI_END---") {
                break;
            }
        }
        let _ = stdout_tx.send(false);
        (false, last_error, stdout_lines)
    });

    // Poll for readiness: check stdout channel and port file + TCP connect
    let ready_timeout = Duration::from_secs(120);
    let start_time = std::time::Instant::now();
    let mut ready = false;
    let mut ready_via_port_file = false;

    while start_time.elapsed() < ready_timeout {
        // Check if stdout thread got the ready signal
        if let Ok(true) = stdout_rx.try_recv() {
            ready = true;
            break;
        }

        // Check if the process has exited (error case)
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }

        // Fallback: check if port file exists and bridge responds to TCP
        if let Ok(Some(port)) = read_port_file(project_path) {
            let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            if TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok() {
                info!("Bridge is ready (port file fallback on port {})", port);
                ready = true;
                ready_via_port_file = true;
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    if !ready {
        // Prevent orphaned JVM process: if child is still running but didn't
        // become ready, kill it and clean up stale files
        if let Ok(None) = child.try_wait() {
            let _ = child.kill();
            let _ = child.wait();
        }
        cleanup_stale_files(project_path).ok();

        let (_, last_error, stdout_lines) = stdout_handle.join().unwrap_or_default();
        let stderr_output = stderr_handle.join().unwrap_or_default();
        let detail = if !last_error.is_empty() {
            format!(": {}", last_error)
        } else if !stderr_output.is_empty() {
            let last_stderr: Vec<_> = stderr_output.iter().rev().take(5).rev().cloned().collect();
            format!(": stderr: {}", last_stderr.join("\n"))
        } else {
            let last_stdout: Vec<_> = stdout_lines.iter().rev().take(10).rev().cloned().collect();
            format!("\nLast stdout:\n{}", last_stdout.join("\n"))
        };
        // Surface an actionable hint when the failure is the (otherwise opaque)
        // OSGi script compile/load failure, instead of just passing it through.
        let combined = format!("{}\n{}", stdout_lines.join("\n"), stderr_output.join("\n"));
        let hint = bridge_failure_hint(&combined);

        match child.try_wait() {
            Ok(Some(status)) => {
                anyhow::bail!("Ghidra process exited with status: {}{}{}", status, detail, hint);
            }
            Ok(None) => {
                anyhow::bail!("Ghidra bridge did not send ready signal{}{}", detail, hint);
            }
            Err(e) => {
                anyhow::bail!("Error checking process status: {}", e);
            }
        }
    }

    // If we discovered readiness via port file, the stdout thread may still be
    // blocking. That's fine - it will terminate when the bridge eventually exits
    // and closes stdout. We intentionally don't join it here.
    if !ready_via_port_file {
        // Stdout thread delivered the signal, safe to join
        drop(stdout_handle);
    }

    // Read port from port file
    let port = read_port_file(project_path)?
        .ok_or_else(|| anyhow::anyhow!("Port file not created by bridge"))?;

    info!("Ghidra bridge started on port {}", port);
    Ok(port)
}

/// Stop the bridge for a project.
pub fn stop_bridge(project_path: &Path) -> Result<()> {
    // Read PID before sending TCP shutdown so we can wait for the JVM to
    // fully exit (release project lock) before returning.
    let pid = read_pid_file(project_path).ok().flatten();

    // Try graceful shutdown via TCP using BridgeClient
    if let Ok(Some(port)) = read_port_file(project_path) {
        let client = BridgeClient::new(port);
        if let Ok(()) = client.shutdown() {
            debug!("Graceful shutdown sent");
        }
    }

    // Wait for the process to exit gracefully, then force-kill if needed
    if let Some(pid) = pid {
        // Wait up to 3 seconds for graceful exit
        for _ in 0..30 {
            if !is_pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // If still alive after waiting, force kill
        if is_pid_alive(pid) {
            warn!("Killing bridge process {} as fallback", pid);
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F", "/T"])
                    .output();
            }

            // Wait for the process to actually die after SIGTERM/taskkill.
            // Without this, the JVM may still hold the project lock when the
            // next bridge tries to start (causes intermittent CI failures).
            for _ in 0..100 {
                if !is_pid_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            // Last resort: SIGKILL if SIGTERM wasn't enough
            #[cfg(unix)]
            if is_pid_alive(pid) {
                warn!("SIGKILL bridge process {} (SIGTERM didn't work)", pid);
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                // Brief wait for SIGKILL to take effect
                for _ in 0..20 {
                    if !is_pid_alive(pid) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    // Clean up files
    cleanup_stale_files(project_path)?;

    info!("Bridge stopped");
    Ok(())
}

/// Get bridge status for a project.
pub fn bridge_status(project_path: &Path) -> Result<BridgeStatus> {
    let port = read_port_file(project_path)?;
    let pid = read_pid_file(project_path)?;

    if let (Some(port), Some(pid)) = (port, pid) {
        if is_pid_alive(pid) {
            let client = BridgeClient::new(port);
            if client.ping().unwrap_or(false) {
                return Ok(BridgeStatus::Running { port, pid });
            }
        }
        // Stale files
        cleanup_stale_files(project_path).ok();
    }

    Ok(BridgeStatus::Stopped)
}

/// Write PID to the PID file for a project.
/// Enables orphan cleanup when Java crashes before writing its own PID file.
/// Java overwrites this value once it binds the ServerSocket.
fn write_pid_file(project_path: &Path, pid: u32) -> Result<()> {
    let path = pid_file_path(project_path)?;
    std::fs::write(&path, pid.to_string())?;
    debug!("Wrote PID {} to {}", pid, path.display());
    Ok(())
}

/// Bridge status
#[derive(Debug)]
pub enum BridgeStatus {
    Running { port: u16, pid: u32 },
    Stopped,
}

/// Compile the embedded bridge script with the given JDK against the Ghidra
/// install's jars, to verify it actually compiles (catches JRE-vs-JDK problems
/// and Ghidra API incompatibilities). Returns the javac error lines on failure.
pub fn compile_check(
    ghidra_install_dir: &Path,
    jdk_home: &Path,
) -> std::result::Result<(), String> {
    #[cfg(windows)]
    let (javac_name, cp_sep) = ("javac.exe", ';');
    #[cfg(not(windows))]
    let (javac_name, cp_sep) = ("javac", ':');

    let javac = jdk_home.join("bin").join(javac_name);
    if !javac.exists() {
        return Err(format!("javac not found at {}", javac.display()));
    }

    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let src = tmp.path().join("GhidraCliBridge.java");
    std::fs::write(&src, JAVA_BRIDGE_SCRIPT).map_err(|e| e.to_string())?;

    let mut classpath = String::new();
    for entry in walkdir::WalkDir::new(ghidra_install_dir)
        .into_iter()
        .flatten()
    {
        if entry.path().extension().and_then(|e| e.to_str()) == Some("jar") {
            classpath.push_str(&entry.path().to_string_lossy());
            classpath.push(cp_sep);
        }
    }
    if classpath.is_empty() {
        return Err("No Ghidra jars found to compile against".to_string());
    }

    let out = std::process::Command::new(&javac)
        .arg("-proc:none")
        .arg("-cp")
        .arg(&classpath)
        .arg("-d")
        .arg(tmp.path().join("out"))
        .arg(&src)
        .output()
        .map_err(|e| format!("Failed to run javac: {}", e))?;

    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let errs: Vec<&str> = stderr
            .lines()
            .filter(|l| l.contains("error:") || l.trim_start().starts_with("symbol:") || l.trim_start().starts_with("location:"))
            .collect();
        if errs.is_empty() {
            Err(stderr.lines().take(20).collect::<Vec<_>>().join("\n"))
        } else {
            Err(errs.join("\n"))
        }
    }
}

/// Detect the OSGi script compile/load failure signature in Ghidra output and
/// return an actionable hint (empty string if the failure looks unrelated).
fn bridge_failure_hint(output: &str) -> String {
    let osgi_fail = output.contains("Failed to get OSGi bundle")
        || output.contains("GhidraScriptLoadException")
        || (output.contains("ClassNotFoundException") && output.contains("GhidraCliBridge"));
    if osgi_fail {
        "\n\nThe Ghidra bridge script failed to compile/load. Common causes:\n  \
         - The Java Ghidra used is a JRE without a compiler (no `javac` / `jdk.compiler` module).\n  \
         - A Ghidra API incompatibility in the bridge script.\n\
         Run `ghidra doctor` to diagnose: it verifies a full JDK and compiles the bridge to show the real error."
            .to_string()
    } else {
        String::new()
    }
}

/// Find the analyzeHeadless script.
pub fn find_headless_script(ghidra_install_dir: &Path) -> Result<PathBuf> {
    let support_dir = ghidra_install_dir.join("support");

    #[cfg(unix)]
    let script_name = "analyzeHeadless";
    #[cfg(windows)]
    let script_name = "analyzeHeadless.bat";

    let script_path = support_dir.join(script_name);

    if script_path.exists() {
        Ok(script_path)
    } else {
        anyhow::bail!("analyzeHeadless not found at: {}", support_dir.display())
    }
}

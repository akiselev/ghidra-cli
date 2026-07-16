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
    /// Open an existing program in the project
    Process { program_name: String },
    /// Open the project without loading a specific program
    Project,
}

/// Embedded Java bridge script
const JAVA_BRIDGE_SCRIPT: &str = include_str!("scripts/GhidraCliBridge.java");

/// Grace period for a bridge to drain accepted program jobs and let Ghidra
/// close the project cleanly before the CLI falls back to process termination.
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 300;

fn parse_shutdown_timeout(raw: Option<&str>) -> Option<Duration> {
    let seconds = raw
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_SECS);
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

fn shutdown_timeout() -> Option<Duration> {
    parse_shutdown_timeout(std::env::var("GHIDRA_CLI_SHUTDOWN_TIMEOUT").ok().as_deref())
}

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
        info!(
            "Bridge already running on port {} (detected after lock)",
            port
        );
        return Ok(port);
    }

    // Clean up any stale port/pid/lock files before starting fresh.
    cleanup_stale_files(project_path)?;
    start_bridge(project_path, ghidra_install_dir, mode)
}

/// Select a full JDK for Ghidra and set `JAVA_HOME` on the command. Ghidra
/// compiles the bridge script at runtime via OSGi and needs javac/jdk.compiler,
/// which a JRE lacks. Setting `JAVA_HOME` on the child overrides Ghidra's
/// PATH-based auto-pick (honored by Ghidra's LaunchSupport on all platforms).
/// If we can't find a JDK, proceed and let Ghidra try — the readiness failure
/// path surfaces an actionable hint.
fn apply_java_home(cmd: &mut Command, ghidra_install_dir: &Path) {
    let explicit_java = crate::config::Config::load()
        .ok()
        .and_then(|c| c.get_java_home());
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
            warn!(
                "No suitable JDK auto-selected; letting Ghidra choose. {}",
                e
            );
        }
    }
}

/// Import a binary into the project using a clean, short-lived `analyzeHeadless
/// -import` run (no long-lived preScript), then return the imported program's
/// name.
///
/// This is the durable way to create a brand-new project. Unlike bootstrapping
/// the persistent bridge with `-import` (which holds the imported program inside
/// HeadlessAnalyzer's transaction for the bridge's whole life and only commits
/// it during teardown — a commit we then race by killing the JVM), this run
/// imports, saves, commits the project, and exits on its own. The persistent
/// bridge can then open the already-committed program in `-process` mode, where
/// saves are durable and no teardown commit is required.
pub fn import_oneshot(
    project_path: &Path,
    binary_path: &Path,
    ghidra_install_dir: &Path,
) -> Result<String> {
    info!("Importing binary into new project (one-shot)...");

    let headless_script = find_headless_script(ghidra_install_dir)?;

    let ghidra_project_dir = project_path.parent().unwrap_or(project_path);
    let ghidra_project_name = project_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    // HeadlessAnalyzer names the imported program after the binary's filename;
    // `-import` has no rename option, so that is the program's domain name.
    let program_name = binary_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .ok_or_else(|| anyhow::anyhow!("Binary path has no filename: {}", binary_path.display()))?;

    let mut cmd = Command::new(&headless_script);
    cmd.arg(ghidra_project_dir)
        .arg(&ghidra_project_name)
        .arg("-import")
        .arg(binary_path)
        .arg("-noanalysis")
        .arg("-overwrite");

    apply_java_home(&mut cmd, ghidra_install_dir);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Own process group so the whole JVM tree is killable as a unit (parity with
    // start_bridge), avoiding orphaned JVMs holding pipes open.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

    info!("Ghidra one-shot import command: {:?}", cmd);
    let mut child = cmd
        .spawn()
        .context("Failed to spawn Ghidra headless import")?;

    // Drain stdout/stderr on threads so the pipes never fill (which would stall
    // the JVM), logging each line and watching for the success/failure markers.
    let stdout = child.stdout.take().expect("stdout should be piped");
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut saw_success = false;
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra import stdout] {}", line);
            if line.contains("Import succeeded") || line.contains("REPORT: Save succeeded") {
                saw_success = true;
            }
        }
        saw_success
    });
    let stderr = child.stderr.take().expect("stderr should be piped");
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut last_error = String::new();
        for line in reader.lines().map_while(Result::ok) {
            info!("[Ghidra import stderr] {}", line);
            if line.contains("ERROR") || line.contains("Exception") || line.contains("Abort") {
                last_error = line.clone();
            }
        }
        last_error
    });

    let status = child
        .wait()
        .context("Failed to wait for Ghidra headless import")?;

    let saw_success = stdout_handle.join().unwrap_or(false);
    let last_error = stderr_handle.join().unwrap_or_default();

    if !status.success() {
        anyhow::bail!(
            "Ghidra import failed (exit {:?}){}",
            status.code(),
            if last_error.is_empty() {
                String::new()
            } else {
                format!(": {}", last_error)
            }
        );
    }
    if !saw_success {
        anyhow::bail!(
            "Ghidra import did not report success{}",
            if last_error.is_empty() {
                String::new()
            } else {
                format!(": {}", last_error)
            }
        );
    }

    info!("One-shot import complete: {}", program_name);
    Ok(program_name)
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

    // Add mode-specific args.
    //
    // `-noanalysis` everywhere: the bridge must bind its socket and signal ready
    // BEFORE any auto-analysis runs, so launch stays bounded. Analysis is driven
    // separately as an unbounded TCP `analyze` operation (which also saves).
    match &mode {
        BridgeStartMode::Process { program_name } => {
            cmd.arg("-process").arg(program_name).arg("-noanalysis");
        }
        BridgeStartMode::Project => {
            cmd.arg("-process").arg("-noanalysis");
        }
    }

    // Add Java bridge script args.
    //
    // `-preScript` (not `-postScript`): a preScript runs after the binary is
    // imported/loaded (so `currentProgram` is set) but before auto-analysis.
    // The bridge binds its ServerSocket inside run(), so as a preScript it comes
    // up as early as possible — decoupling a bounded launch from unbounded
    // analysis. (`-noanalysis` skips the analysis phase anyway.)
    cmd.arg("-scriptPath")
        .arg(scripts_dir.to_str().unwrap())
        .arg("-preScript")
        .arg("GhidraCliBridge.java")
        .arg(port_file.to_str().unwrap());

    apply_java_home(&mut cmd, ghidra_install_dir);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Spawn the JVM tree in its own process group so the whole tree (the
    // analyzeHeadless wrapper AND the java grandchild) is killable as a unit.
    // Without this, killing only the direct child leaves an orphaned JVM that
    // holds the stdout/stderr pipes open — which previously hung the CLI.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // New group whose id equals the child (wrapper) pid — the group leader.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }

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

    // Wait for the bridge to become ready.
    //
    // The wait is liveness-aware: we keep waiting as long as the child process
    // is alive (loading a large binary is part of this bounded launch) and only
    // give up if the process exits before becoming ready, or a generous absolute
    // safety cap (`launch_timeout_secs`) is exceeded. The cap is a safety net,
    // NOT the normal exit path — analysis runs afterwards as an unbounded TCP op.
    //
    // Primary readiness signal: port file present + TCP ping succeeds (robust on
    // Windows, where stdout piped through analyzeHeadless.bat → cmd.exe → java.exe
    // is unreliable). The stdout JSON ready signal is kept only as a fast path.
    let launch_timeout = crate::config::Config::load()
        .map(|c| c.get_launch_timeout())
        .unwrap_or_else(|_| Duration::from_secs(180));

    let mut ready_port: Option<u16> = None;
    let check_ready = || {
        let signaled = matches!(stdout_rx.try_recv(), Ok(true));
        if let Ok(Some(port)) = read_port_file(project_path) {
            if signaled || BridgeClient::new(port).ping().unwrap_or(false) {
                ready_port = Some(port);
                return true;
            }
        }
        false
    };
    let check_alive = || matches!(child.try_wait(), Ok(None));

    let outcome = poll_until_ready(
        Duration::from_millis(250),
        launch_timeout,
        check_ready,
        check_alive,
    );

    match outcome {
        ReadyOutcome::Ready => {
            let port = ready_port
                .or_else(|| read_port_file(project_path).ok().flatten())
                .ok_or_else(|| anyhow::anyhow!("Port file not created by bridge"))?;
            // Success path: DETACH the reader threads — do NOT join. The JVM
            // keeps the pipes open for its whole lifetime, so joining here would
            // block forever. They terminate on their own when the bridge exits.
            drop(stdout_handle);
            drop(stderr_handle);
            info!("Ghidra bridge started on port {}", port);
            Ok(port)
        }
        ReadyOutcome::Exited | ReadyOutcome::TimedOut => {
            // Kill the ENTIRE process tree FIRST so the pipes close; only then is
            // it safe to join the reader threads. Joining before killing was the
            // original hang: a surviving JVM held the pipes open forever.
            kill_process_tree(&mut child);
            cleanup_stale_files(project_path).ok();

            let (_, last_error, stdout_lines) = stdout_handle.join().unwrap_or_default();
            let stderr_output = stderr_handle.join().unwrap_or_default();
            let detail = if !last_error.is_empty() {
                format!(": {}", last_error)
            } else if !stderr_output.is_empty() {
                let last_stderr: Vec<_> =
                    stderr_output.iter().rev().take(5).rev().cloned().collect();
                format!(": stderr: {}", last_stderr.join("\n"))
            } else {
                let last_stdout: Vec<_> =
                    stdout_lines.iter().rev().take(10).rev().cloned().collect();
                format!("\nLast stdout:\n{}", last_stdout.join("\n"))
            };
            // Surface an actionable hint when the failure is the (otherwise
            // opaque) OSGi script compile/load failure.
            let combined = format!("{}\n{}", stdout_lines.join("\n"), stderr_output.join("\n"));
            let hint = bridge_failure_hint(&combined);

            match outcome {
                ReadyOutcome::Exited => anyhow::bail!(
                    "Ghidra process exited before the bridge became ready{}{}",
                    detail,
                    hint
                ),
                ReadyOutcome::TimedOut => anyhow::bail!(
                    "Ghidra bridge did not become ready within {}s{}{}",
                    launch_timeout.as_secs(),
                    detail,
                    hint
                ),
                ReadyOutcome::Ready => unreachable!(),
            }
        }
    }
}

/// Outcome of the bridge readiness wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyOutcome {
    /// The bridge bound its socket and responded.
    Ready,
    /// The child process exited before the bridge became ready.
    Exited,
    /// The absolute launch safety cap was exceeded while the child was alive.
    TimedOut,
}

/// Liveness-aware readiness state machine. Factored out (closures injected) so
/// the three outcomes can be unit-tested without a real Ghidra process.
///
/// - `check_ready`: returns true once the bridge is listening (port + ping).
/// - `check_alive`: returns true while the launched process is still running.
fn poll_until_ready(
    poll_interval: Duration,
    launch_timeout: Duration,
    mut check_ready: impl FnMut() -> bool,
    mut check_alive: impl FnMut() -> bool,
) -> ReadyOutcome {
    let start = std::time::Instant::now();
    loop {
        if check_ready() {
            return ReadyOutcome::Ready;
        }
        if !check_alive() {
            // Re-check readiness once: the socket may have bound in the same
            // instant the process record flipped to exited (it shouldn't, but
            // this avoids a benign race reporting a false failure).
            if check_ready() {
                return ReadyOutcome::Ready;
            }
            return ReadyOutcome::Exited;
        }
        if start.elapsed() >= launch_timeout {
            return ReadyOutcome::TimedOut;
        }
        std::thread::sleep(poll_interval);
    }
}

/// Kill an entire spawned process tree (group), then reap the direct child.
///
/// Safe to call whether or not the process is still alive. On unix this relies
/// on the child having been spawned with `process_group(0)` (the child is the
/// group leader, so its pid is the group id). On windows `taskkill /T` walks
/// the tree. After this returns, the child's stdio pipes are closed, so any
/// reader threads can be joined without blocking.
fn kill_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i32;
        unsafe {
            libc::killpg(pgid, libc::SIGTERM);
        }
        // Brief grace window for the group to exit on SIGTERM.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if !is_pid_alive(child.id()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Force-kill the whole group. ESRCH on an already-dead group is harmless.
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .output();
    }
    let _ = child.wait();
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

    // Wait for the process to drain accepted jobs and exit cleanly, then
    // force-kill only after the configured grace period. A value of 0 waits
    // indefinitely, which is useful for very large analysis jobs.
    if let Some(pid) = pid {
        let timed_out = match shutdown_timeout() {
            Some(timeout) => {
                let deadline = std::time::Instant::now() + timeout;
                while is_pid_alive(pid) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                is_pid_alive(pid)
            }
            None => {
                while is_pid_alive(pid) {
                    std::thread::sleep(Duration::from_millis(100));
                }
                false
            }
        };

        if timed_out {
            warn!(
                "Bridge {} did not finish draining before GHIDRA_CLI_SHUTDOWN_TIMEOUT; killing as fallback",
                pid
            );
            #[cfg(unix)]
            unsafe {
                // Kill the whole process group (the JVM was spawned into the
                // analyzeHeadless wrapper's group). Fall back to a single-pid
                // kill if the group id can't be resolved.
                let pgid = libc::getpgid(pid as i32);
                if pgid > 0 {
                    libc::killpg(pgid, libc::SIGTERM);
                } else {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
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
                    let pgid = libc::getpgid(pid as i32);
                    if pgid > 0 {
                        libc::killpg(pgid, libc::SIGKILL);
                    } else {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
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
            .filter(|l| {
                l.contains("error:")
                    || l.trim_start().starts_with("symbol:")
                    || l.trim_start().starts_with("location:")
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn shutdown_timeout_defaults_and_supports_unbounded_wait() {
        assert_eq!(
            parse_shutdown_timeout(None),
            Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
        );
        assert_eq!(
            parse_shutdown_timeout(Some(" 45 ")),
            Some(Duration::from_secs(45))
        );
        assert_eq!(parse_shutdown_timeout(Some("0")), None);
        assert_eq!(
            parse_shutdown_timeout(Some("invalid")),
            Some(Duration::from_secs(DEFAULT_SHUTDOWN_TIMEOUT_SECS))
        );
    }

    #[test]
    fn ready_when_socket_binds_while_alive() {
        // Becomes ready on the 3rd poll; process stays alive throughout.
        let polls = Cell::new(0);
        let outcome = poll_until_ready(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || {
                polls.set(polls.get() + 1);
                polls.get() >= 3
            },
            || true,
        );
        assert_eq!(outcome, ReadyOutcome::Ready);
    }

    #[test]
    fn exited_when_process_dies_before_ready() {
        let alive = Cell::new(true);
        let outcome = poll_until_ready(
            Duration::from_millis(1),
            Duration::from_secs(5),
            || false, // never ready
            || {
                let was = alive.get();
                alive.set(false); // dies after the first liveness check
                was
            },
        );
        assert_eq!(outcome, ReadyOutcome::Exited);
    }

    #[test]
    fn timed_out_when_never_ready_but_alive() {
        let outcome = poll_until_ready(
            Duration::from_millis(5),
            Duration::from_millis(30), // tiny cap
            || false,                  // never ready
            || true,                   // always alive
        );
        assert_eq!(outcome, ReadyOutcome::TimedOut);
    }

    /// Spawn a shell that itself spawns a long-lived child, then prove
    /// `kill_process_tree` takes out the whole group (not just the wrapper).
    #[cfg(unix)]
    #[test]
    fn kill_process_tree_kills_whole_group() {
        use std::os::unix::process::CommandExt;

        let mut cmd = std::process::Command::new("sh");
        // Print the grandchild's pid, then sleep both shell and grandchild.
        cmd.arg("-c").arg("sleep 300 & echo $! ; wait");
        cmd.stdout(Stdio::piped());
        cmd.process_group(0);
        let mut child = cmd.spawn().expect("spawn sh");

        // Read the grandchild (sleep) pid that the shell printed.
        let mut line = String::new();
        {
            let stdout = child.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            reader.read_line(&mut line).expect("read grandchild pid");
        }
        let grandchild: u32 = line.trim().parse().expect("parse grandchild pid");

        assert!(is_pid_alive(grandchild), "grandchild should be alive");
        kill_process_tree(&mut child);

        // The group-kill should have reaped the grandchild too. Allow a brief
        // moment for the kernel to deliver SIGKILL.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline && is_pid_alive(grandchild) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !is_pid_alive(grandchild),
            "grandchild {} should be dead after kill_process_tree",
            grandchild
        );
    }
}

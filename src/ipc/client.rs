//! Bridge client for direct communication with the Java bridge.
//!
//! Connects directly to the Java GhidraCliBridge via TCP.
//! No intermediate daemon process is needed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use tracing::debug;

use super::protocol::{BridgeError, BridgeRequest, BridgeResponse};

/// Commands that never run against "the current program", so they must not
/// carry `expect_program` (control commands, and the program-switching ones).
const NO_PROGRAM_CHECK: &[&str] = &[
    "ping",
    "status",
    "bridge_info",
    "job_status",
    "job_cancel",
    "shutdown",
    "open_program",
    "import",
    "list_programs",
    "program_close",
    "program_delete",
];

/// A process-unique request ID: pid, wall-clock nanos and a counter.
fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{:x}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Short budget for the control requests the client makes on its own behalf
/// (describing or cancelling a timed-out job). Control commands never queue.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// Default socket read timeout for short, interactive commands, in seconds.
///
/// Exclusive jobs (writes, analyze, plain scripts) block every other program
/// job, and reads can queue behind a full read pool, so a command may wait its
/// turn while control requests remain responsive. This budget must therefore be generous
/// enough to outlast whatever is ahead of it. Override with
/// `GHIDRA_CLI_READ_TIMEOUT` (seconds); `0` means block indefinitely.
const DEFAULT_READ_TIMEOUT_SECS: u64 = 300;

/// Wall-clock budget for establishing the initial TCP connection, retried with
/// backoff while the bridge is starting, restarting, or its accept backlog is
/// momentarily saturated. Override with `GHIDRA_CLI_CONNECT_DEADLINE` (seconds).
const DEFAULT_CONNECT_DEADLINE_SECS: u64 = 60;

/// Interpret a seconds string into an optional [`Duration`]: `0` means "no
/// timeout" (`None`), and an absent/unparseable value falls back to `default`.
fn parse_secs(raw: Option<&str>, default: u64) -> Option<Duration> {
    let secs = raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default);
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Parse a seconds-valued env var into an optional [`Duration`], where `0` means
/// "no timeout" (`None`) and an unset/invalid value falls back to `default`.
fn secs_env(var: &str, default: u64) -> Option<Duration> {
    parse_secs(std::env::var(var).ok().as_deref(), default)
}

/// Read timeout for short, interactive commands. `None` blocks indefinitely.
fn default_read_timeout() -> Option<Duration> {
    secs_env("GHIDRA_CLI_READ_TIMEOUT", DEFAULT_READ_TIMEOUT_SECS)
}

/// Read timeout for long-running operations (analyze/import of large binaries).
///
/// `None` means block until the bridge responds or the connection drops — these
/// ops can legitimately exceed any fixed cap. Power users can impose a ceiling
/// via `GHIDRA_CLI_OP_TIMEOUT` (seconds); `0` or unset means unbounded.
fn long_op_timeout() -> Option<Duration> {
    match std::env::var("GHIDRA_CLI_OP_TIMEOUT")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(0) | None => None,
        Some(secs) => Some(Duration::from_secs(secs)),
    }
}

/// Native decompiler execution budget sent to Ghidra. Ghidra defines zero as
/// unbounded; that is the default because large, valid functions routinely take
/// longer than its historical 30-second background-analysis default.
fn decompile_timeout_secs() -> u32 {
    std::env::var("GHIDRA_CLI_DECOMPILE_TIMEOUT")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Default cap, in MB, on a single decompiler response. Ghidra's own default
/// is 50 MB, which large switch-heavy functions exceed ("Response buffer size
/// exceeded"). Must match `DEFAULT_DECOMPILE_MAX_PAYLOAD_MB` in the Java bridge.
pub const DEFAULT_DECOMPILE_MAX_PAYLOAD_MB: u32 = 512;

/// Largest accepted payload limit: Ghidra computes `mb << 20` in a Java `int`.
pub const MAX_DECOMPILE_PAYLOAD_MB: u32 = 2047;

/// Resolve the decompiler payload limit: an explicit flag wins, then the
/// `GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB` value, then the default. Values are
/// clamped to `1..=MAX_DECOMPILE_PAYLOAD_MB`; an unparseable env value is ignored.
fn resolve_max_payload_mb(flag: Option<u32>, env: Option<&str>) -> u32 {
    flag.or_else(|| env.and_then(|s| s.trim().parse::<u32>().ok()))
        .unwrap_or(DEFAULT_DECOMPILE_MAX_PAYLOAD_MB)
        .clamp(1, MAX_DECOMPILE_PAYLOAD_MB)
}

fn decompile_max_payload_mb(flag: Option<u32>) -> u32 {
    resolve_max_payload_mb(
        flag,
        std::env::var("GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB")
            .ok()
            .as_deref(),
    )
}

/// Overall connect budget, from `GHIDRA_CLI_CONNECT_DEADLINE` (min 1s).
fn connect_deadline() -> Duration {
    let secs = std::env::var("GHIDRA_CLI_CONNECT_DEADLINE")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_CONNECT_DEADLINE_SECS);
    Duration::from_secs(secs.max(1))
}

/// A connect error that means "not yet", not "never": the bridge is (re)starting
/// or its accept backlog is momentarily full. Safe to wait and retry.
fn is_transient_connect_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionReset | ConnectionAborted | TimedOut | AddrInUse | WouldBlock
    )
}

/// Connect to the bridge, waiting out transient failures.
///
/// A busy bridge still accepts connections and queues program jobs, so connect
/// normally succeeds immediately and the wait happens on the read. But during
/// bridge (re)start or saturated client capacity, connect can
/// fail transiently; rather than surfacing that as a hard error we retry with
/// exponential backoff until [`connect_deadline`] elapses. Only pre-send connect
/// failures are retried — nothing has been written yet — so this stays safe for
/// non-idempotent commands (rename/comment/patch).
fn connect_with_retry(addr: &std::net::SocketAddr) -> Result<TcpStream> {
    let budget = connect_deadline();
    let deadline = std::time::Instant::now() + budget;
    let mut backoff = Duration::from_millis(100);
    let mut last_err: Option<std::io::Error> = None;
    loop {
        match TcpStream::connect_timeout(addr, Duration::from_secs(10)) {
            Ok(stream) => return Ok(stream),
            Err(e) if is_transient_connect_error(&e) && std::time::Instant::now() < deadline => {
                debug!("bridge connect transient ({e}); retrying in {backoff:?}");
                last_err = Some(e);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(2));
            }
            Err(e) => {
                let e = last_err.unwrap_or(e);
                anyhow::bail!(
                    "Failed to connect to bridge on port {} after waiting {}s: {}. \
                     Is the bridge running? Check `ghidra status`.",
                    addr.port(),
                    budget.as_secs(),
                    e
                );
            }
        }
    }
}

/// One line describing a job from a protocol-3 `job_status` response.
fn describe_job(job: &serde_json::Value) -> String {
    let id = job.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let state = job
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let lane = job.get("lane").and_then(|v| v.as_str()).unwrap_or("?");
    let elapsed = job.get("elapsed_ms").and_then(|v| v.as_u64()).unwrap_or(0) as f64 / 1000.0;
    let mut text = format!(" — job {id} ({lane} lane) is {state} after {elapsed:.0}s");
    if let Some(pos) = job.get("queue_position").and_then(|v| v.as_u64()) {
        text.push_str(&format!(", queue position {pos} (0 = next)"));
    }
    if let Some(blockers) = job.get("blocked_by").and_then(|v| v.as_array()) {
        if !blockers.is_empty() {
            let ids: Vec<String> = blockers.iter().map(|b| b.to_string()).collect();
            text.push_str(&format!(", blocked by job(s) {}", ids.join(", ")));
        }
    }
    text
}

/// Fallback for bridges that cannot look up a job by request ID.
fn describe_queue_summary(status: &serde_json::Value) -> String {
    let Some(depth) = status.get("queue_depth").and_then(|v| v.as_u64()) else {
        return String::new();
    };
    let mut text = format!(" — the bridge has {depth} queued job(s)");
    if let Some(active) = status.get("active_job").filter(|v| !v.is_null()) {
        let id = active.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let cmd = active
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let elapsed = active
            .get("elapsed_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as f64
            / 1000.0;
        text.push_str(&format!("; active job {id} ({cmd}) has run {elapsed:.0}s"));
    }
    text.push_str(" (this bridge predates per-job lookup; its job was not cancelled)");
    text
}

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
    expect_program: Option<String>,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            expect_program: None,
        }
    }

    /// Tag every program request with the program it must run against. A
    /// protocol-3 bridge then refuses the job with a `program_mismatch` error
    /// if another client switched programs in the meantime; older bridges
    /// ignore the tag.
    pub fn set_expected_program(&mut self, program: Option<String>) {
        self.expect_program = program;
    }

    /// Get the port this client connects to.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Send a command to the bridge and return the result.
    ///
    /// Uses [`DEFAULT_READ_TIMEOUT`] for the response wait — suitable for short,
    /// interactive commands. Long-running ops should use
    /// [`Self::send_command_with_timeout`] with an unbounded read timeout.
    pub fn send_command(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(command, args, default_read_timeout())
    }

    /// Send a command with an explicit socket read timeout.
    ///
    /// `read_timeout = None` blocks until the bridge responds or the connection
    /// drops — required for operations whose duration is unbounded (e.g. analysis
    /// of a large binary), which would otherwise spuriously time out.
    pub fn send_command_with_timeout(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
        read_timeout: Option<Duration>,
    ) -> Result<serde_json::Value> {
        let control = NO_PROGRAM_CHECK.contains(&command);
        let request = BridgeRequest {
            command: command.to_string(),
            args,
            request_id: (!control).then(new_request_id),
            expect_program: if control {
                None
            } else {
                self.expect_program.clone()
            },
        };
        self.send_request(&request, read_timeout)
    }

    fn send_request(
        &self,
        request: &BridgeRequest,
        read_timeout: Option<Duration>,
    ) -> Result<serde_json::Value> {
        let command = request.command.as_str();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        let mut stream = connect_with_retry(&addr)?;
        // `None` => blocking reads (no timeout). A long analysis can exceed any
        // fixed cap, so callers route those ops through here with `None`.
        stream.set_read_timeout(read_timeout).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        let request_json = serde_json::to_string(request)?;
        debug!("Sending: {}", request_json);

        writeln!(stream, "{}", request_json)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        match reader.read_line(&mut response_line) {
            // EOF before any response: bridge closed the socket without replying.
            Ok(0) => anyhow::bail!(
                "Bridge closed the connection without responding to '{}' \
                 (it may have crashed or been restarted). Retry, or check `ghidra status`.",
                command
            ),
            Ok(_) => {}
            // A read timeout here means the bridge is up (we connected) but hasn't
            // reached our queued request in time — almost always because it is busy
            // serving another agent. Say where the job is, then cancel it so it
            // does not run for nobody (bug 005), and give the knob to wait longer.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                drop(reader);
                let detail = request
                    .request_id
                    .as_deref()
                    .map(|id| self.describe_and_cancel_pending(id))
                    .unwrap_or_default();
                anyhow::bail!(
                    "Bridge did not respond within {}s while running '{}'{}. Inspect \
                     `ghidra jobs`, raise the wait via GHIDRA_CLI_READ_TIMEOUT (seconds; \
                     0 = wait indefinitely), or use GHIDRA_CLI_OP_TIMEOUT for long \
                     analyze/import operations.",
                    read_timeout.map(|d| d.as_secs()).unwrap_or(0),
                    command,
                    detail
                )
            }
            Err(e) => return Err(e.into()),
        }

        debug!("Received: {}", response_line.trim());

        let response: BridgeResponse = serde_json::from_str(&response_line)?;

        match response.status.as_str() {
            "success" => Ok(response.data.unwrap_or(json!({}))),
            "error" => {
                let msg = response
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string());
                if let Some(code) = response.code {
                    return Err(BridgeError { code, message: msg }.into());
                }
                anyhow::bail!("{}", msg)
            }
            "shutdown" if command == "shutdown" => Ok(json!({"status": "shutdown"})),
            // Never turn an unexpected envelope into a silent success.
            other => anyhow::bail!(
                "Bridge returned an unexpected response status '{other}' for '{command}'"
            ),
        }
    }

    /// After a read timeout: report where our job is (queue position, the jobs
    /// blocking it) and ask the bridge to cancel it. Only control requests are
    /// sent, so nothing queues. Against a bridge older than protocol 3, which
    /// cannot look jobs up by request ID, this reports the queue summary and
    /// does NOT send a cancel (an ID-less cancel would hit another client's job).
    fn describe_and_cancel_pending(&self, request_id: &str) -> String {
        let status = match self.control("job_status", json!({"request_id": request_id})) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };
        let Some(job) = status.get("job") else {
            return describe_queue_summary(&status);
        };
        let mut text = describe_job(job);
        let state = job.get("state").and_then(|v| v.as_str()).unwrap_or("");
        if matches!(
            state,
            "queued" | "waiting_lock" | "running" | "cancel_requested"
        ) {
            match self.control("job_cancel", json!({"request_id": request_id})) {
                Ok(r) => {
                    let new_state = r.get("state").and_then(|v| v.as_str()).unwrap_or("?");
                    text.push_str(&format!("; asked the bridge to cancel it ({new_state})"));
                }
                Err(e) => text.push_str(&format!("; cancel failed: {e}")),
            }
        }
        text
    }

    /// Send a control command with a short timeout and no request ID.
    fn control(&self, command: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let request = BridgeRequest {
            command: command.to_string(),
            args: Some(args),
            request_id: None,
            expect_program: None,
        };
        self.send_request(&request, Some(CONTROL_TIMEOUT))
    }

    /// Check if bridge is responding.
    ///
    /// Uses a short read timeout so readiness polling stays snappy (a missing
    /// or unbound socket fails fast rather than blocking).
    pub fn ping(&self) -> Result<bool> {
        match self.send_command_with_timeout("ping", None, Some(Duration::from_secs(5))) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Shutdown the bridge.
    pub fn shutdown(&self) -> Result<()> {
        self.send_command("shutdown", None)?;
        Ok(())
    }

    /// Get bridge status.
    pub fn status(&self) -> Result<serde_json::Value> {
        self.send_command("status", None)
    }

    /// Get one job, or the full bridge job status when no ID is supplied.
    pub fn job_status(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_status", Some(json!({"job_id": job_id})))
    }

    /// Request cooperative cancellation of a job. With no ID, cancel the active job.
    pub fn cancel_job(&self, job_id: Option<u64>) -> Result<serde_json::Value> {
        self.send_command("job_cancel", Some(json!({"job_id": job_id})))
    }

    /// Get bridge info (current program, project name, program count, uptime).
    pub fn bridge_info(&self) -> Result<serde_json::Value> {
        self.send_command("bridge_info", None)
    }

    /// List functions. `tags` restricts to functions carrying ALL of the given
    /// tags (server-side filter); `untagged` restricts to functions with no tags.
    pub fn list_functions(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
        tags: &[String],
        untagged: bool,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_functions",
            Some(json!({
                "limit": limit,
                "filter": filter,
                "tags": tags,
                "untagged": untagged,
            })),
        )
    }

    /// Decompile a function.
    ///
    /// `max_payload_mb` overrides the decompiler response-size limit; `None`
    /// falls back to `GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB`, then the default.
    pub fn decompile(
        &self,
        address: String,
        with_vars: bool,
        with_params: bool,
        max_payload_mb: Option<u32>,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(
            "decompile",
            Some(json!({
                "address": address,
                "with_vars": with_vars,
                "with_params": with_params,
                "timeout_secs": decompile_timeout_secs(),
                "max_payload_mb": decompile_max_payload_mb(max_payload_mb),
            })),
            long_op_timeout(),
        )
    }

    /// List strings.
    pub fn list_strings(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_strings",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    /// List imports.
    pub fn list_imports(&self) -> Result<serde_json::Value> {
        self.send_command("list_imports", None)
    }

    /// List exports.
    pub fn list_exports(&self) -> Result<serde_json::Value> {
        self.send_command("list_exports", None)
    }

    /// Get memory map.
    pub fn memory_map(&self) -> Result<serde_json::Value> {
        self.send_command("memory_map", None)
    }

    /// Get program info.
    pub fn program_info(&self) -> Result<serde_json::Value> {
        self.send_command("program_info", None)
    }

    /// Get cross-references to an address.
    pub fn xrefs_to(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_to", Some(json!({"address": address})))
    }

    /// Get cross-references from an address.
    pub fn xrefs_from(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_from", Some(json!({"address": address})))
    }

    /// Import a binary. Unbounded read timeout: importing a large binary can
    /// take a long time.
    pub fn import_binary(
        &self,
        binary_path: &str,
        program: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(
            "import",
            Some(json!({"binary_path": binary_path, "program": program})),
            long_op_timeout(),
        )
    }

    /// Analyze the current program. Unbounded read timeout: full auto-analysis
    /// can exceed any fixed cap on large/complex binaries.
    pub fn analyze(&self) -> Result<serde_json::Value> {
        self.send_command_with_timeout("analyze", None, long_op_timeout())
    }

    /// List programs in the project.
    pub fn list_programs(&self) -> Result<serde_json::Value> {
        self.send_command("list_programs", None)
    }

    /// Open/switch to a program.
    pub fn open_program(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("open_program", Some(json!({"program": program})))
    }

    // === Extended commands (symbols, types, comments, etc.) ===

    pub fn symbol_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_list",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    pub fn symbol_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_get", Some(json!({"name": name})))
    }

    pub fn symbol_create(&self, address: &str, name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_create",
            Some(json!({"address": address, "name": name})),
        )
    }

    pub fn symbol_delete(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_delete", Some(json!({"name": name})))
    }

    pub fn symbol_rename(&self, old_name: &str, new_name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_rename",
            Some(json!({"old_name": old_name, "new_name": new_name})),
        )
    }

    pub fn type_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command("type_list", Some(json!({"limit": limit, "filter": filter})))
    }

    /// List function tags (all tags, or one function's tags).
    pub fn tag_list(
        &self,
        limit: Option<usize>,
        function: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "tag_list",
            Some(json!({"limit": limit, "function": function})),
        )
    }

    /// Get the member functions of a tag.
    pub fn tag_get(&self, name: &str, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("tag_get", Some(json!({"name": name, "limit": limit})))
    }

    pub fn type_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("type_get", Some(json!({"name": name})))
    }

    pub fn type_create(&self, definition: &str) -> Result<serde_json::Value> {
        self.send_command("type_create", Some(json!({"definition": definition})))
    }

    pub fn type_apply(&self, address: &str, type_name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "type_apply",
            Some(json!({"address": address, "type_name": type_name})),
        )
    }

    pub fn comment_list(
        &self,
        limit: Option<usize>,
        filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_list",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    pub fn comment_get(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_get", Some(json!({"address": address})))
    }

    pub fn comment_set(
        &self,
        address: &str,
        text: &str,
        comment_type: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_set",
            Some(json!({
                "address": address,
                "text": text,
                "comment_type": comment_type,
            })),
        )
    }

    pub fn comment_delete(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_delete", Some(json!({"address": address})))
    }

    pub fn graph_calls(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("graph_calls", Some(json!({"limit": limit})))
    }

    pub fn graph_callers(&self, function: &str, depth: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callers",
            Some(json!({"function": function, "depth": depth})),
        )
    }

    pub fn graph_callees(&self, function: &str, depth: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callees",
            Some(json!({"function": function, "depth": depth})),
        )
    }

    pub fn graph_export(&self, format: &str) -> Result<serde_json::Value> {
        self.send_command("graph_export", Some(json!({"format": format})))
    }

    pub fn find_string(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_string", Some(json!({"pattern": pattern})))
    }

    pub fn find_bytes(&self, hex: &str) -> Result<serde_json::Value> {
        self.send_command("find_bytes", Some(json!({"hex": hex})))
    }

    pub fn find_function(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_function", Some(json!({"pattern": pattern})))
    }

    pub fn find_calls(&self, function: &str) -> Result<serde_json::Value> {
        self.send_command("find_calls", Some(json!({"function": function})))
    }

    pub fn find_crypto(&self) -> Result<serde_json::Value> {
        self.send_command("find_crypto", None)
    }

    pub fn find_interesting(&self) -> Result<serde_json::Value> {
        self.send_command("find_interesting", None)
    }

    pub fn diff_programs(&self, program1: &str, program2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_programs",
            Some(json!({"program1": program1, "program2": program2})),
        )
    }

    pub fn diff_functions(&self, func1: &str, func2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_functions",
            Some(json!({"func1": func1, "func2": func2})),
        )
    }

    pub fn patch_bytes(&self, address: &str, hex: &str) -> Result<serde_json::Value> {
        self.send_command("patch_bytes", Some(json!({"address": address, "hex": hex})))
    }

    pub fn patch_nop(&self, address: &str, count: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "patch_nop",
            Some(json!({"address": address, "count": count})),
        )
    }

    pub fn patch_export(&self, output: &str) -> Result<serde_json::Value> {
        self.send_command("patch_export", Some(json!({"output": output})))
    }

    pub fn disasm(
        &self,
        address: &str,
        num_instructions: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "disasm",
            Some(json!({"address": address, "count": num_instructions})),
        )
    }

    /// Disassemble a function's whole body (bug 004). `limit = None` returns
    /// every instruction. A protocol-3 bridge reports `total_instructions` and
    /// `truncated`; older bridges ignore `function_body`/`limit` and return
    /// their old 10-instruction default, which the caller detects and flags.
    pub fn disasm_function(
        &self,
        address: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let limit = limit.map(|n| n.min(i32::MAX as usize)).unwrap_or(0);
        self.send_command(
            "disasm",
            Some(json!({"address": address, "function_body": true, "limit": limit})),
        )
    }

    pub fn stats(&self) -> Result<serde_json::Value> {
        self.send_command("stats", None)
    }

    pub fn script_run(
        &self,
        script_path: &str,
        args: &[String],
        expect: &[serde_json::Value],
        allow_empty: bool,
        read_only: bool,
    ) -> Result<serde_json::Value> {
        let mut payload = json!({"path": script_path, "args": args});
        if read_only {
            payload["read_only"] = json!(true);
        }
        if !expect.is_empty() {
            payload["expect"] = serde_json::Value::Array(expect.to_vec());
            payload["allow_empty"] = json!(allow_empty);
        }
        self.send_command("script_run", Some(payload))
    }

    pub fn script_python(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_python", Some(json!({"code": code})))
    }

    pub fn script_java(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_java", Some(json!({"code": code})))
    }

    pub fn script_list(&self) -> Result<serde_json::Value> {
        self.send_command("script_list", None)
    }

    pub fn program_close(&self) -> Result<serde_json::Value> {
        self.send_command("program_close", None)
    }

    pub fn program_delete(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("program_delete", Some(json!({"program": program})))
    }

    pub fn program_export(&self, format: &str, output: Option<&str>) -> Result<serde_json::Value> {
        self.send_command(
            "program_export",
            Some(json!({"format": format, "output": output})),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decompile_timeout_secs, is_transient_connect_error, parse_secs, resolve_max_payload_mb,
        DEFAULT_DECOMPILE_MAX_PAYLOAD_MB, MAX_DECOMPILE_PAYLOAD_MB,
    };
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

    #[test]
    fn parse_secs_zero_means_no_timeout() {
        assert_eq!(parse_secs(Some("0"), 300), None);
    }

    #[test]
    fn parse_secs_reads_value() {
        assert_eq!(parse_secs(Some("12"), 300), Some(Duration::from_secs(12)));
        assert_eq!(parse_secs(Some("  7 "), 300), Some(Duration::from_secs(7)));
    }

    #[test]
    fn parse_secs_falls_back_when_absent_or_garbage() {
        assert_eq!(parse_secs(None, 42), Some(Duration::from_secs(42)));
        assert_eq!(parse_secs(Some("nope"), 42), Some(Duration::from_secs(42)));
        // Fallback default of 0 still means "no timeout".
        assert_eq!(parse_secs(None, 0), None);
    }

    #[test]
    fn decompile_timeout_defaults_to_unbounded() {
        // Avoid changing the process environment because this suite runs tests
        // concurrently. The assertion applies to the normal unset case.
        if std::env::var_os("GHIDRA_CLI_DECOMPILE_TIMEOUT").is_none() {
            assert_eq!(decompile_timeout_secs(), 0);
        }
    }

    #[test]
    fn max_payload_defaults_above_ghidra_default() {
        assert_eq!(
            resolve_max_payload_mb(None, None),
            DEFAULT_DECOMPILE_MAX_PAYLOAD_MB
        );
        // Ghidra's own default is 50 MB; ours must be larger to be useful.
        const { assert!(DEFAULT_DECOMPILE_MAX_PAYLOAD_MB > 50) };
    }

    #[test]
    fn max_payload_flag_overrides_env() {
        assert_eq!(resolve_max_payload_mb(Some(1024), Some("64")), 1024);
        assert_eq!(resolve_max_payload_mb(None, Some(" 64 ")), 64);
        assert_eq!(
            resolve_max_payload_mb(None, Some("lots")),
            DEFAULT_DECOMPILE_MAX_PAYLOAD_MB
        );
    }

    #[test]
    fn max_payload_is_clamped_to_ghidra_int_range() {
        assert_eq!(resolve_max_payload_mb(None, Some("0")), 1);
        assert_eq!(
            resolve_max_payload_mb(None, Some("4096")),
            MAX_DECOMPILE_PAYLOAD_MB
        );
        assert_eq!(
            resolve_max_payload_mb(Some(9999), None),
            MAX_DECOMPILE_PAYLOAD_MB
        );
    }

    #[test]
    fn transient_connect_errors_are_retryable() {
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::TimedOut,
        ] {
            assert!(
                is_transient_connect_error(&Error::from(kind)),
                "{kind:?} should be retryable"
            );
        }
    }

    #[test]
    fn permanent_connect_errors_are_not_retryable() {
        for kind in [ErrorKind::NotFound, ErrorKind::PermissionDenied] {
            assert!(
                !is_transient_connect_error(&Error::from(kind)),
                "{kind:?} should not be retryable"
            );
        }
    }
}

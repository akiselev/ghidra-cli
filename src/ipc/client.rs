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

use super::protocol::{BridgeRequest, BridgeResponse};

/// Default socket read timeout for short, interactive commands, in seconds.
///
/// Ghidra program access is serialized through the bridge's explicit job queue,
/// so a command that arrives while another is in flight waits its turn while
/// control requests remain responsive. This budget must therefore be generous
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

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self { port }
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
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        let mut stream = connect_with_retry(&addr)?;
        // `None` => blocking reads (no timeout). A long analysis can exceed any
        // fixed cap, so callers route those ops through here with `None`.
        stream.set_read_timeout(read_timeout).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        let request = BridgeRequest {
            command: command.to_string(),
            args,
        };

        let request_json = serde_json::to_string(&request)?;
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
            // serving another agent. Surface that plainly, with the knob to wait longer.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                anyhow::bail!(
                    "Bridge did not respond within {}s while running '{}' — the program job is \
                     still queued or running. Inspect `ghidra jobs`, raise the wait via \
                     GHIDRA_CLI_READ_TIMEOUT (seconds; 0 = wait indefinitely), or use \
                     GHIDRA_CLI_OP_TIMEOUT for long analyze/import operations.",
                    read_timeout.map(|d| d.as_secs()).unwrap_or(0),
                    command
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
                anyhow::bail!("{}", msg)
            }
            "shutdown" => Ok(json!({"status": "shutdown"})),
            _ => Ok(response.data.unwrap_or(json!({}))),
        }
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

    /// List functions.
    pub fn list_functions(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "list_functions",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    /// Decompile a function.
    pub fn decompile(
        &self,
        address: String,
        with_vars: bool,
        with_params: bool,
    ) -> Result<serde_json::Value> {
        self.send_command_with_timeout(
            "decompile",
            Some(json!({
                "address": address,
                "with_vars": with_vars,
                "with_params": with_params,
                "timeout_secs": decompile_timeout_secs(),
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

    pub fn stats(&self) -> Result<serde_json::Value> {
        self.send_command("stats", None)
    }

    pub fn script_run(
        &self,
        script_path: &str,
        args: &[String],
        expect: &[serde_json::Value],
        allow_empty: bool,
    ) -> Result<serde_json::Value> {
        let mut payload = json!({"path": script_path, "args": args});
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
    use super::{decompile_timeout_secs, is_transient_connect_error, parse_secs};
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

# Ghidra Bridge Module (`src/ghidra/`)

Manages the Java bridge process lifecycle and Ghidra installation/setup.

## Files

| File | Purpose |
|------|---------|
| `bridge.rs` | Bridge process management: start, stop, status, liveness check |
| `setup.rs` | Ghidra download, installation, Java version check |
| `mod.rs` | Module root, `GhidraClient` for project/installation operations |
| `scripts/GhidraCliBridge.java` | Java bridge server (TCP, 80+ command handlers, runs inside Ghidra JVM) |

## Bridge Lifecycle

```
CLI calls ensure_bridge_running()
  |
  +-- is bridge already running? (port file + PID alive + TCP probe)
  |     yes -> return existing port
  |     no  -> clean up stale files, call start_bridge()
  |
  v
start_bridge()
  |
  1. Write GhidraCliBridge.java to ~/.config/ghidra-cli/scripts/
  2. Spawn: analyzeHeadless <project_dir> <project_name> -process [<program>] -noanalysis -preScript GhidraCliBridge.java <port_file_path>
  3. Write PID file immediately from Rust (child.id())       <-- enables orphan cleanup
  4. Read stdout line by line, wait for {"status":"ready"}
  5. Java bridge: binds ServerSocket(0), writes port file, overwrites PID file
  6. Return port number to caller
```

The bridge always launches with `-preScript -noanalysis`, so it binds its socket
right after the project (and optional program) loads — *before* any analysis —
and reports ready fast. Analysis is not part of launch; it runs afterwards as an
unbounded TCP `analyze` operation. Importing a new binary is a separate,
short-lived `analyzeHeadless -import -noanalysis` run that commits the program to
the project before the persistent bridge opens it in `-process` mode.

### PID File Write Sequence

Two writes happen to the PID file:

1. **Rust writes immediately** after `child.spawn()` -- uses the OS-level child PID. This ensures the PID file exists even if Java crashes before binding the ServerSocket, enabling cleanup of orphaned JVM processes.
2. **Java overwrites later** once the bridge binds its ServerSocket and is ready to accept connections. The Java PID value is the same process, but the write confirms the bridge reached its ready state.

The Rust write uses `.ok()` (ignores errors) because it is best-effort. The Java write is the authoritative one.

### Failure Cleanup

If the bridge fails to start (ready signal not received):

1. Check if child process is still running via `child.try_wait()`
2. If running: `child.kill()` then `child.wait()` to prevent orphaned JVM
3. Call `cleanup_stale_files()` to remove any port/PID files
4. Return error with diagnostic details from stderr/stdout

## Liveness Detection

### `is_bridge_running(project_path) -> Option<u16>`

Returns `Some(port)` if the bridge is alive, `None` otherwise. Checks in order:

1. Port file exists and contains a valid u16
2. PID file exists and contains a valid u32
3. PID is alive (`kill(pid, 0)` on Unix)
4. TCP connect to `127.0.0.1:{port}` succeeds

Returns the port directly so callers never need a separate `read_port_file()` call. This eliminates TOCTOU races where the port file could change between a liveness check and a subsequent read.

### `bridge_status(project_path) -> BridgeStatus`

Stronger verification than `is_bridge_running`: uses `BridgeClient::new(port).ping()` instead of raw TCP connect. Returns `BridgeStatus::Running { port, pid }` or `BridgeStatus::Stopped`.

### Responsive control plane and read/write program lanes

Command dispatch no longer treats a failed pre-flight ping as proof that the bridge is
dead. Socket handling is separate from Ghidra program execution, and program jobs run in
lanes (protocol 3, bugs 001/005/006):

```text
TCP acceptor -> bounded client pool -> control commands (immediate)
                                  |-> exclusive FIFO -> GhidraScript thread   (write lock)
                                  \-> read / read-heavy FIFOs -> read pool    (read lock)
```

`ping`, `status`, `bridge_info`, `job_status`, `job_cancel`, and `shutdown` run on the
control plane using thread-safe snapshots. Writes, `open_program`, `program_close`,
`analyze`, `import` and non-`--read-only` `script_run` are exclusive: they run on the
original `GhidraScript.run()` thread under the write side of a fair
`ReentrantReadWriteLock`. Commands in `READ_COMMANDS` run on a bounded read pool
(`GHIDRA_CLI_READ_THREADS`, default `min(8, cores/2)`, at least 2; `0` = all exclusive)
under the read side. Long reads (`HEAVY_READ_COMMANDS`) may occupy at most pool − 1
threads and cheap reads are dequeued first. Handlers use the per-thread `jobMonitor()`
instead of GhidraScript's shared `monitor` field, and each read thread keeps its own
`DecompInterface`. Only exclusive jobs refresh the `bridge_info` program snapshot.

Each job keeps its client socket. A watchdog probes queued and running jobs every 2 s
(1 ms read: EOF = client gone); gone clients' queued jobs are dropped as `abandoned`, and
running reads/scripts are cooperatively cancelled. A job is probed again just before it
runs. Requests may carry `request_id` (for `job_status`/`job_cancel` lookups after a client
timeout) and `expect_program` (refused with `program_mismatch` if another client switched
programs). Unknown commands are rejected immediately with code `unknown_command`.

Each queue is bounded at 256 program jobs. Connection handlers only parse and
enqueue; they do not block while a program future is pending. Completed futures hand socket
writes to a separate bounded response pool, preserving the existing synchronous
request/response protocol without starving controls behind waiting clients. Status retains
the 100 most recent jobs and exposes active progress, queued work, cancellation state, and
elapsed time. Cancellation uses a per-job `TaskMonitorAdapter`; active cancellation is
cooperative, while a job that has not started can be removed from the queue immediately.

See `ipc/client.rs`: `connect_with_retry()` waits out transient connect failures (bridge
(re)start / saturated client capacity) with backoff up to
`GHIDRA_CLI_CONNECT_DEADLINE` (default 60s). A program request waits up to
`GHIDRA_CLI_READ_TIMEOUT` (default 300s; `0` = indefinite), while long analyze/import
operations use `GHIDRA_CLI_OP_TIMEOUT` (`0` or unset = indefinite). Use `ghidra jobs` to
inspect work and `ghidra cancel [JOB_ID]` to request cancellation.

`shutdown` stops accepting new work and drains every program job accepted before it. The
Rust lifecycle waits up to `GHIDRA_CLI_SHUTDOWN_TIMEOUT` (default 300s; `0` = indefinite)
before force termination. This replaces the old three-second window that could kill a
healthy bridge while it was finishing work or closing the project.

## BridgeClient Adoption

`bridge.rs` sends no commands over TCP directly. All command communication goes through `BridgeClient` (in `src/ipc/client.rs`):

- `stop_bridge()` uses `BridgeClient::new(port).shutdown()` for graceful shutdown
- `bridge_status()` uses `BridgeClient::new(port).ping()` for liveness verification
- `is_bridge_running()` still uses raw `TcpStream::connect` for the lightweight probe (no command round-trip needed)

Rationale: `bridge.rs` originally had its own `BridgeRequest`/`BridgeResponse` structs and `send_command()`/`send_typed_command()` functions that duplicated the types and logic in `ipc/protocol.rs` and `ipc/client.rs`. Consolidating to BridgeClient eliminated ~80 lines of duplicate TCP code and the duplicate type definitions.

## Per-Project Isolation

Each project gets unique port/PID files via MD5 hash of the project path:

- **Port file**: `~/.local/share/ghidra-cli/bridge-{md5}.port`
- **PID file**: `~/.local/share/ghidra-cli/bridge-{md5}.pid`

This allows multiple bridges to run simultaneously for different projects.

## Start Modes

`BridgeStartMode` selects how the persistent bridge opens the project. Both use
`-preScript -noanalysis`; neither analyzes at launch.

| Mode | analyzeHeadless Args | Use Case |
|------|---------------------|----------|
| `Process { program_name }` | `-process <program_name> -noanalysis` | Open a specific existing program |
| `Project` | `-process -noanalysis` | Open the project without loading a program (e.g. `program list`, auto-start) |

Importing a binary is not a start mode. It happens in a separate short-lived
`analyzeHeadless -import -noanalysis` run that commits the program to the project;
the persistent bridge then opens it in `Process` mode and analysis runs over TCP.

## Stale File Cleanup

`cleanup_stale_files(project_path)` removes both port and PID files. Called:

- When `ensure_bridge_running` detects stale files (dead PID or unreachable port)
- When `start_bridge` fails (ready signal not received)
- When `bridge_status` finds stale files
- When `stop_bridge` completes (normal cleanup)

# Ghidra Bridge Module (`src/ghidra/`)

Manages the Java bridge process lifecycle and Ghidra installation/setup.

## Files

| File | Purpose |
|------|---------|
| `bridge.rs` | Bridge process management: start, stop, status, liveness check |
| `setup.rs` | Ghidra download, installation, Java version check |
| `mod.rs` | Module root, `GhidraClient` for project/installation operations |
| `scripts/GhidraCliBridge.java` | Java bridge server (TCP, 40+ command handlers, runs inside Ghidra JVM) |

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
  2. Spawn: analyzeHeadless <project_dir> <project_name> [-import <binary> | -process <program> -noanalysis] -postScript GhidraCliBridge.java <port_file_path>
  3. Write PID file immediately from Rust (child.id())       <-- enables orphan cleanup
  4. Read stdout line by line, wait for {"status":"ready"}
  5. Java bridge: binds ServerSocket(0), writes port file, overwrites PID file
  6. Return port number to caller
```

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

### Pre-flight liveness (no ping gate on the hot path)

Command dispatch used to call a `verify_bridge()` helper that pinged the bridge (5s
timeout) before running the requested command. That was **removed**: it conflated a
*busy* bridge with a *dead* one. The bridge is single-threaded, so while it serves one
request it cannot answer a ping — under concurrent agents the ping timed out and the whole
command failed with "Bridge not responding to ping", even though the bridge was healthy and
would have served the request as soon as it was free.

`is_bridge_running()` already proves liveness (port file + PID alive + TCP accept) right
before dispatch, and the OS accept backlog (50) queues concurrent connections, so a busy
bridge simply makes the client **wait its turn** on the read rather than fail. See
`ipc/client.rs`: `connect_with_retry()` waits out transient connect failures (bridge
(re)start / saturated backlog) with backoff up to `GHIDRA_CLI_CONNECT_DEADLINE` (default
60s), and the read blocks up to `GHIDRA_CLI_READ_TIMEOUT` (default 300s; `0` = indefinite).

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

| Mode | analyzeHeadless Args | Use Case |
|------|---------------------|----------|
| `Import { binary_path }` | `-import <binary_path>` | First import of a binary |
| `Process { program_name }` | `-process <program_name> -noanalysis` | Open existing program for queries |

Import mode auto-analyzes during headless processing. Process mode skips analysis (`-noanalysis`) since the program was already analyzed during import.

## Stale File Cleanup

`cleanup_stale_files(project_path)` removes both port and PID files. Called:

- When `ensure_bridge_running` detects stale files (dead PID or unreachable port)
- When `start_bridge` fails (ready signal not received)
- When `bridge_status` finds stale files
- When `stop_bridge` completes (normal cleanup)

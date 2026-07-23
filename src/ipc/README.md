# IPC Module (`src/ipc/`)

Single TCP implementation for CLI-to-bridge communication. All command sending goes through `BridgeClient`.

## Files

| File | Purpose |
|------|---------|
| `client.rs` | `BridgeClient` -- the canonical client for all bridge commands |
| `protocol.rs` | `BridgeRequest` / `BridgeResponse` wire format structs |

## BridgeClient

`BridgeClient` is the single entry point for sending commands to the Java bridge. It holds a port number and creates a new TCP connection per command (connection-per-request model).

```rust
let client = BridgeClient::new(port);
let result = client.list_functions(Some(100), None)?;
```

### Connection Model

Each `send_command()` call:

1. Opens a new `TcpStream` to `127.0.0.1:{port}`
2. Sets read timeout (300s) and write timeout (30s)
3. Serializes `BridgeRequest` to JSON, writes as a single line (`writeln!`)
4. Reads one line of response, deserializes as `BridgeResponse`
5. Returns `Ok(data)` for success, `Err` for error status

This is connection-per-request, not persistent. The Java bridge's `ServerSocket.accept()` loop handles one connection at a time, processes the command, and returns to accept. Ghidra `Program` objects are not thread-safe, so sequential processing is required.

### Response Handling

| Status | Client Behavior |
|--------|----------------|
| `"success"` | Return `data` field (or empty `{}`) |
| `"error"` | Return `Err` with `message` field |
| `"shutdown"` | Return `Ok({"status":"shutdown"})` |
| Other | Return `data` field (or empty `{}`) |

### Available Commands

BridgeClient wraps all bridge commands as typed methods:

| Category | Methods |
|----------|---------|
| Core | `ping()`, `shutdown()`, `status()`, `bridge_info()`, `job_status()`, `cancel_job()` |
| Program | `program_info()`, `list_programs()`, `open_program()`, `program_close()`, `program_delete()`, `program_export()` |
| Import/Analysis | `import_binary()`, `analyze()` |
| Functions | `list_functions()`, `decompile()` |
| Data | `list_strings()`, `list_imports()`, `list_exports()`, `memory_map()` |
| Xrefs | `xrefs_to()`, `xrefs_from()` |
| Symbols | `symbol_list()`, `symbol_get()`, `symbol_create()`, `symbol_delete()`, `symbol_rename()` |
| Types | `type_list()`, `type_get()`, `type_create()`, `type_apply()` |
| Comments | `comment_list()`, `comment_get()`, `comment_set()`, `comment_delete()` |
| Search | `find_string()`, `find_bytes()`, `find_function()`, `find_calls()`, `find_crypto()`, `find_interesting()` |
| Graph | `graph_calls()`, `graph_callers()`, `graph_callees()`, `graph_export()` |
| Diff | `diff_programs()`, `diff_functions()` |
| Patch | `patch_bytes()`, `patch_nop()`, `patch_export()` |
| Disasm | `disasm()` |
| Stats | `stats()` |
| Scripts | `script_run()`, `script_python()`, `script_java()`, `script_list()` |
| Batch | `batch()` |

All methods delegate to `send_command(command_name, args)`. For commands not covered by a typed method, use `send_command()` directly.

## Wire Format

### Request (`BridgeRequest`)

```json
{"command":"list_functions","args":{"limit":100,"filter":"main"}}
```

- `command`: string, required -- the command name
- `args`: object, optional -- command-specific arguments (omitted from JSON when `None`)

Sent as a single newline-terminated JSON line over TCP.

### Response (`BridgeResponse`)

```json
{"status":"success","data":{"functions":[...]},"message":null}
```

- `status`: string -- `"success"`, `"error"`, or `"shutdown"`
- `data`: optional -- command result payload (absent on error)
- `message`: optional string -- error description (absent on success)

Read as a single newline-terminated JSON line from TCP.

## Single Implementation Rationale

`bridge.rs` originally contained its own `BridgeRequest`/`BridgeResponse` structs and `send_command()`/`send_typed_command()` functions. This duplicated the types in `protocol.rs` and the logic in `client.rs`. The duplication was eliminated by:

1. Deleting `BridgeRequest`, `BridgeResponse<T>`, `send_command()`, and `send_typed_command()` from `bridge.rs`
2. Having `bridge.rs` import and use `BridgeClient` from `ipc/client.rs` for `stop_bridge()` and `bridge_status()`
3. `protocol.rs` is now the single source of truth for the wire format types

The only raw `TcpStream` usage remaining outside this module is in `bridge.rs` -- both `is_bridge_running()` and `ensure_bridge_running()` use a TCP connect probe (no request/response) for lightweight liveness detection.

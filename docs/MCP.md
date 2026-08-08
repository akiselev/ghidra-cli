# ghidra-cli MCP Server

Native MCP (Model Context Protocol) server exposing the ghidra-cli command surface as first-class tools.

Agents connect directly (stdio or HTTP). No shell + JSON parsing required.

## Quick Start

```bash
# stdio transport (primary for local agents)
ghidra mcp stdio

# HTTP transport (streamable JSON-RPC over POST)
ghidra mcp http --listen 127.0.0.1:0
# prints: ghidra-mcp-http listening on 127.0.0.1:<port>

# Optional bearer token (also GHIDRA_MCP_TOKEN)
ghidra mcp http --listen 127.0.0.1:8080 --token secret
```

With a bridge already running for a project:

```bash
ghidra --project myproj start
ghidra --project myproj mcp stdio
```

## Transports

### stdio

Line-based JSON-RPC 2.0 on stdin/stdout. One request JSON object per line.

### HTTP (slice 1.5)

- Binds `--listen` (use port `0` for ephemeral).
- **Localhost-only**: non-loopback peers receive HTTP 403.
- Optional `Authorization: Bearer <token>` when `--token` / `GHIDRA_MCP_TOKEN` is set.
- Endpoints:
  - `POST /` or `POST /mcp` — JSON-RPC body (same methods as stdio)
  - `GET /health` — liveness
  - `GET /tools` — tool list (same registry as `tools/list`)
- Same tool registry, envelopes, and error shapes as stdio.

#### Minimal curl examples

```bash
# discover port if you used :0 (read the "listening on" line)
PORT=8080

# tools/list
curl -sS -X POST "http://127.0.0.1:${PORT}/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# ping
curl -sS -X POST "http://127.0.0.1:${PORT}/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}'

# decompile (requires running bridge + project context on the server)
curl -sS -X POST "http://127.0.0.1:${PORT}/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"decompile","arguments":{"target":"main"}}}'
```

With token:

```bash
curl -sS -X POST "http://127.0.0.1:${PORT}/mcp" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer secret' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

## Stable Envelope

Every `tools/call` result places a JSON envelope in `content[0].text`:

```json
{
  "status": "success" | "error",
  "command": "decompile",
  "provenance": {
    "tool_version": "0.2.1",
    "timestamp": "2026-08-08T12:00:00Z",
    "project": "myproj",
    "program": "sample",
    "binary_sha256": null,
    "ghidra_version": null
  },
  "data": { },
  "next_steps": [ "suggested follow-up tools + brief rationale" ],
  "recovery_suggestions": [ "actionable hints when status=error" ],
  "artifacts": []
}
```

- **next_steps**: guided hints to reduce thrashing.
- **recovery_suggestions**: populated on errors (missing bridge, conflict, verification/expect failure, bad args).
- **artifacts**: filled by `script_run` when `expect` is used (manifests include path, hash, row counts).

## Mutations and Durability (slice 1.4)

Write tools (`patch_*`, symbol/type/comment/function mutations, `script_run`) use the **same bridge job queue and per-mutation transactions** as the CLI. There is no separate write path.

Durability rules (same as CLI):

1. Mutate via a focused tool.
2. Re-read / verify (disasm, decompile, list).
3. For long-lived trust, **reopen in a fresh process** and re-check the invariant.
4. On conflict or verification failure, follow `recovery_suggestions` (jobs, abort transaction, re-expect artifacts).

Example recovery text for a locked program: inspect `ghidra jobs`, wait or cancel, reopen fresh, re-verify.

## Script / Batch (slice 1.6)

### script_run

```json
{
  "name": "script_run",
  "arguments": {
    "path": "/path/to/script.py",
    "args": ["--flag"],
    "expect": [{"path": "/tmp/out.csv", "min_rows": 1}],
    "allow_empty": false
  }
}
```

On success, envelope `artifacts[]` carries per-file manifests (sha256, rows, etc.) when expect was declared.

Inline `script_java` / `script_python` remain bridge-level; prefer `script_run` with a file path.

### batch

Accepts an array of `{ "name", "arguments" }` tool calls. Executes them sequentially in-process (same registry). Returns:

```json
{
  "data": {
    "count": 2,
    "results": [
      { "index": 0, "name": "ping", "status": "success", "envelope": { ... } },
      { "index": 1, "name": "patch_bytes", "status": "error", "envelope": { ... } }
    ]
  }
}
```

Nested `batch` is rejected.

## Capability Negotiation + Schema Versioning (slice 1.7)

`initialize` returns:

- `serverInfo.name` = `ghidra-mcp`
- `serverInfo.version` = CLI crate version
- `serverInfo.schema_version` = tool schema version string (currently `"1"`)
- `ghidraCapabilities`: CLI version, transports, feature flags (`job_queue`, `mutations`, `script_expect_artifacts`, `diff`, `summarize`, `pcode`, `transactions`, …), optional bridge connection fields (`ghidra_version`, `binary_sha256` when connected)

Dedicated tool: `capabilities`.

### Tool schema evolution rule

| Change | Action |
|--------|--------|
| Add optional input field or new optional output key | Non-breaking; keep name; same `schema_version` |
| Add required input field or remove/rename field | Breaking: bump `schema_version` and either rename tool (`foo_v2`) or add `_vN` suffix; keep old tool until deprecated |
| Change semantics of existing field | Breaking: same as above |
| New tool | Non-breaking |

Migration notes for agents: always read `tools/list` schemas; prefer `schema_version` + tool name over hard-coded assumption; on unknown tool, re-list.

## Tool Catalog (focused tools)

Read / query: `ping`, `project_list`, `function_list`, `decompile`, `disasm`, `xrefs_to`, `xrefs_from`, `strings_list`, `symbols_list`, `memory_map`, `types_list`, `comments_list`, `find_*`, `graph_*`, `list_imports`, `list_exports`, `program_info`, `stats`, `script_list`, `capabilities`

Mutations: `patch_bytes`, `patch_nop`, `patch_export`, `create_function`, `rename_function`, `delete_function`, `function_set_*`, `set_var_type`, `symbol_*`, `comment_set`, `comment_delete`, `type_*`, `script_run`, `transaction_*`

Analysis helpers: `summarize`, `diff_programs`, `diff_functions`, `pcode`, `batch`

### Decompile extra context (guaranteed)

`decompile` always includes:

- `nearby_xrefs` (may be empty array/object)
- `callers` (may be empty)
- `namespace` (may be `""`)

Optional args: `max_xrefs` (default 50), `caller_depth` (default 2).

## Context (project / program)

- Pass `--project` / `--program` when starting the MCP server.
- Tools that need a bridge error with recovery if none is running (they do not auto-start).

## Security (HTTP)

- Default: loopback only.
- Optional bearer token for same-host agents.
- No OAuth / multi-tenant auth in this release.

## Testing

- Unit tests (no Ghidra): envelope shape, recovery_suggestions, tools/list registry, batch offline, initialize capabilities, HTTP bind + tools/list.
- Gated live tests (`require_ghidra!`): stdio bridge tools, mutation durability when present.

## Related CLI Surfaces

| Goal | CLI |
|------|-----|
| Triage report | `ghidra summarize` / `ghidra triage` |
| P-code | `ghidra pcode <target>` |
| Transactions | `ghidra transaction begin\|commit\|abort` |
| JSON envelope | `ghidra --envelope --json …` (or always for summarize/pcode/transaction) |

## Documentation Map

- README.md — quick MCP start
- docs/MCP.md — this file
- AGENTS.md — agent workflows
- PLAN-mcp-server.md — historical slice plan
- skills/triage-decomp-patch-export.md — example workflow skill

## License

Same as ghidra-cli (GPL-3.0). See LICENSE.

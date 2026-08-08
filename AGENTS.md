# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS!** If Ghidra is not installed, the tests MUST fail. `require_ghidra!()` panics when `ghidra doctor` fails.
2. **DEFAULT OUTPUT FORMAT** should be human and agent readable, NOT JSON. Use `--json` and `--pretty` for JSON output. Exception: when stdout is not a TTY (piped/scripted), the default auto-detects to `JsonCompact` for machine consumption — this is standard Unix pipe convention.

## Architecture

ghidra-cli uses a **direct bridge architecture**:
- CLI connects directly to a Java bridge running inside Ghidra's JVM via TCP
- The bridge is a GhidraScript (`GhidraCliBridge.java`) started via `analyzeHeadless -postScript`
- Bridge binds `ServerSocket(0)` on localhost, writes port/PID files for discovery
- One bridge per project, identified by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Import/Analyze commands auto-start the bridge if not running
- No separate Rust daemon process — the Java bridge IS the persistent server

## Native MCP (prefer over shell-out)

```bash
ghidra --project myproj start
ghidra --project myproj mcp stdio          # JSON-RPC line protocol
ghidra mcp http --listen 127.0.0.1:0       # same tools over HTTP POST /mcp
```

- Every `tools/call` returns a stable envelope: `status`, `provenance`, `data`, `next_steps`, `recovery_suggestions`, `artifacts`.
- Mutations use the same job queue/transactions as the CLI; on failure read `recovery_suggestions` and re-verify in a fresh process.
- `decompile` always includes `nearby_xrefs`, `callers`, `namespace` (possibly empty).
- `batch` accepts an array of `{name, arguments}`; `script_run` supports `args` / `expect` / `allow_empty` and surfaces manifests under `artifacts[]`.
- `initialize` / `capabilities` report CLI version, feature flags, and schema version.

Full catalog: `docs/MCP.md`. Example workflow: `skills/triage-decomp-patch-export.md`.

### CLI helpers (same capabilities)

```bash
ghidra summarize --focus crypto            # triage report with confidence tags
ghidra pcode main --max-ops 50             # p-code listing
ghidra data-flow main --focus r0           # defs/uses over p-code
ghidra type recover 0x401000               # structure field guesses + confidence
ghidra find similar --mode all             # string/crypto similarity
ghidra diff explain build_a build_b        # readable dual-program delta
ghidra diff transfer build_a build_b       # copy labels/comments for matches
ghidra program firmware-summarize          # summarize each program (single lane)
ghidra transaction begin --name edit
ghidra transaction commit
ghidra --envelope --json function list     # stamp provenance on legacy JSON
```

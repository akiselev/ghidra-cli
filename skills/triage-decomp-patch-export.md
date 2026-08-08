# Skill: Triage → Decompile → Patch → Export

Example agent workflow using ghidra-cli (CLI or native MCP). Prefer MCP tools when available so you do not shell out and parse ad-hoc JSON.

## Preconditions

```bash
ghidra doctor
ghidra --project myproj start --program sample
# MCP:
ghidra --project myproj mcp stdio
```

## 1. Triage / summarize

**MCP:** `summarize` with `focus` = `all` | `crypto` | `strings` | `imports`

**CLI:** `ghidra --project myproj --json summarize` (or `triage`)

Expect structured sections + `findings[]` with `confidence` tags. Pick high-confidence targets.

## 2. List and decompile

**MCP:** `function_list` → `decompile` on a target

Decompile always returns:

- `code` / signature
- `nearby_xrefs` (may be empty)
- `callers` (may be empty)
- `namespace` (may be `""`)
- `next_steps`

Optional: `pcode` for raw ops / defined varnodes.

## 3. Cross-check

**MCP:** `xrefs_to`, `graph_callers`, `find_string` / `find_crypto` as needed.

Use `next_steps` from each response instead of inventing tool chains.

## 4. Mutate safely

Prefer an explicit transaction when batching writes:

1. `transaction_begin` (name optional)
2. Mutations: `comment_set`, `rename_function`, `symbol_create`, `patch_bytes` / `patch_nop`, type tools
3. `transaction_commit` or `transaction_abort`

On error, read `recovery_suggestions` (jobs, reopen fresh, expect artifacts).

## 5. Verify durability

1. `disasm` / `decompile` the changed site
2. Optionally stop the bridge and start again; re-check the invariant
3. `patch_export` or program export for the final binary artifact

## 6. Script with expect (optional)

**MCP `script_run`:**

```json
{
  "path": "/path/to/export.py",
  "args": [],
  "expect": [{"path": "/tmp/out.csv", "min_rows": 1}],
  "allow_empty": false
}
```

Envelope `artifacts[]` carries manifests (hashes, row counts).

## Batch macro

```json
{
  "name": "batch",
  "arguments": {
    "commands": [
      {"name": "summarize", "arguments": {"focus": "crypto"}},
      {"name": "function_list", "arguments": {"limit": 10}}
    ]
  }
}
```

Per-item `status` + nested envelope.

## Diff two builds

Import both programs into one project, then:

- MCP: `diff_programs` → `diff_explain` → `diff_transfer` (labels/comments) → `diff_functions` for hot spots
- CLI: `ghidra diff explain a b` then `ghidra diff transfer a b`

Full interactive Version Tracking UI is out of scope; this is the headless match/transfer/explain surface.

## Multi-program firmware pass

```bash
ghidra program firmware-summarize --include img1 --include img2
# MCP: firmware_summarize / programs_foreach
```

Opens each program sequentially on the single execution lane.

## Notes

- Mutations share the CLI job queue / transaction model.
- HTTP MCP: `ghidra mcp http --listen 127.0.0.1:0` (see docs/MCP.md curl examples).
- Use `--envelope --json` on CLI when you want provenance on legacy list commands.

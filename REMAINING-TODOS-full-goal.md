# Remaining Work for Full Active Goal (Items 1–7)

Status update (2026-08-08): MCP base complete; deferred extras (HTTP SSE progress,
headless transfer/explain, deeper primitives, multi-program convenience) shipped.

## Item 1: Native MCP — **complete**

See `REMAINING-TODOS-mcp.md`. HTTP long-job SSE progress via `?stream=1` / `Accept: text/event-stream`.

## Item 2: LLM-optimized tool design — **shipped**

- Decompile extra context, next_steps/recovery, compact schemas, `--envelope`

## Item 3: Binary diffing / Version Tracker — **headless shipped**

- `diff_programs` name-set match + dual provenance
- `diff_transfer` labels/comments for matched names
- `diff_explain` agent-readable delta
- `diff_functions` decompile-level
- Full interactive GUI VT: out of band (optional later)

## Item 4: High-level analysis helpers — **shipped**

- `summarize` / `triage` + `similarity` / `find similar` with confidence tags

## Item 5: Deeper primitives — **shipped**

- `pcode`, `data_flow` / `data-flow`, `structure_recover` / `type recover`
- Explicit transactions

## Item 6: Packaging — **in-repo**

- Dockerfile, Homebrew formula, doctor recovery suggestions

## Item 7: Agent extras — **shipped**

- Skill workflow, envelopes, multi-program `programs_foreach` / `firmware_summarize`

## Truly optional / out-of-band (not blocking)

- Publish Docker image to a registry
- Submit Homebrew formula upstream
- Full interactive Ghidra Version Tracking GUI session
- SSE continuous push for multi-minute jobs (current path: progress frames + final result)

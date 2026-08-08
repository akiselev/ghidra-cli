# Remaining TODOs for Native MCP Server (Active Goal Item 1)

Status: **Slices 1.1–1.7 complete** (2026-08-08). MCP base criteria met.

## Completed

| Slice | Status |
|-------|--------|
| 1.1 Scaffolding + ping | Done |
| 1.2 Bridge-backed tools + decompile extra context | Done |
| 1.3 Stdio parity for core surface | Done (prior sign-off) |
| 1.4 Mutations + recovery_suggestions + provenance + durability tests | Done |
| 1.5 Streamable HTTP (real server, token, equivalence) | Done |
| 1.6 script_run expect/artifacts + local batch array | Done |
| 1.7 initialize/capabilities + schema versioning docs | Done |

## Cross-cutting acceptance

- Stable envelopes on every tools/call path (success + error)
- Focused tools (no raw passthrough)
- Decompile guarantees `nearby_xrefs`, `callers`, `namespace`
- next_steps + recovery_suggestions
- docs/MCP.md + AGENTS.md + README updated
- Unit tests (no Ghidra) + gated live tests (mutation durability, HTTP launch, stdio)

## Optional follow-ups (non-blocking)

- SSE streaming for long-running jobs over HTTP
- Full Version Tracking session API beyond `diff_programs` / `diff_functions`
- Inline script_java/script_python first-class tools (currently prefer script_run files)

## References

- `src/mcp.rs`, `docs/MCP.md`, `tests/daemon_tests.rs`
- `skills/triage-decomp-patch-export.md`

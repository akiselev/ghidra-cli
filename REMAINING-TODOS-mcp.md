# Remaining TODOs for Native MCP Server

Status: **Complete** including deferred HTTP SSE progress (2026-08-08).

## Completed

| Slice / extra | Status |
|---------------|--------|
| 1.1–1.7 MCP base | Done |
| HTTP SSE long-job progress (`?stream=1`) | Done |
| diff_transfer / diff_explain | Done |
| data_flow, structure_recover, similarity | Done |
| programs_foreach / firmware_summarize | Done |

## Optional later (non-blocking)

- Continuous SSE for multi-minute jobs with live percent from JobTaskMonitor
- Full GUI Version Tracking session API
- Inline script_java/script_python tools

## References

- `src/mcp.rs`, `src/extras.rs`, `docs/MCP.md`, `tests/daemon_tests.rs`

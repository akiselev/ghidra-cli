# Plan: Deferred extras (HTTP progress, VT transfer, deeper primitives, multi-program)

Status: implementing under active goal (finish planned extras).

## Surfaces

| Area | CLI | MCP | Bridge |
|------|-----|-----|--------|
| HTTP long-job progress | n/a | SSE on POST `/mcp?stream=1` or `Accept: text/event-stream` | job_status polling when connected |
| Match (existing) | `diff programs` | `diff_programs` | name-set match |
| Transfer analysis | `diff transfer` | `diff_transfer` | open both, copy labels/comments for matches |
| Explain delta | `diff explain` | `diff_explain` | pure assembly from match report + optional bridge refresh |
| Structure recover | `type recover` | `structure_recover` | field guesses at address |
| Data-flow | `pcode flow` / `data-flow` | `data_flow` | uses/defs from pcode |
| Similarity | `find similar` | `similarity` | string/crypto compare with confidence |
| Multi-program | `programs foreach` / `firmware summarize` | `programs_foreach` | sequential open_program + tool |

## Safety

- Single program execution lane: open/switch only; no concurrent mutators.
- Transfer is explicit opt-in mutation; uses transactions where available.

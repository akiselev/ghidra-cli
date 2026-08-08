# Remaining Work for Full Active Goal (Items 1–7)

Status update (2026-08-08): Item 1 MCP base (1.1–1.7) complete. Items 2–7 shipped as focused first versions below.

## Item 1: Native MCP — **complete**

See `REMAINING-TODOS-mcp.md`.

## Item 2: LLM-optimized tool design — **shipped (base)**

- Decompile extra context guaranteed fields + max_xrefs/caller_depth params
- next_steps / recovery_suggestions on MCP paths
- Compact tool schemas via shared `tool_definitions()`
- CLI `--envelope` for provenance on demand; summarize/pcode/transaction always envelope on JSON

## Item 3: Binary diffing / Version Tracker — **minimal surface**

- MCP + existing CLI: `diff_programs`, `diff_functions` with envelopes
- Full interactive VT session not in scope; headless match/delta is the shipped path
- Documented in docs/MCP.md and skills workflow

## Item 4: High-level analysis helpers — **shipped**

- CLI: `ghidra summarize` / `triage --focus ...`
- MCP: `summarize` tool with confidence-tagged findings
- Assembled from existing find_crypto / imports / stats / strings

## Item 5: Deeper primitives — **shipped (base)**

- `pcode` (CLI + MCP + Java bridge handler)
- Explicit `transaction begin|commit|abort` (CLI + MCP + bridge)
- Structure recovery remains Ghidra analyzer / type tools (`type_create`, `type_apply`, fields)

## Item 6: Packaging — **in-repo**

- `Dockerfile` (build + run docs)
- `Formula/ghidra-cli.rb` Homebrew formula (in-repo)
- `ghidra doctor` recovery suggestions for common install failures

## Item 7: Agent extras — **shipped**

- `skills/triage-decomp-patch-export.md`
- MCP provenance envelopes everywhere; CLI `--envelope` + auto for new commands
- Multi-program/firmware convenience deferred (optional; not required)

## Optional later

- Publish Docker image to registry
- Submit Homebrew formula upstream
- Full Ghidra Version Tracking session transfer UX
- Structure recovery “guess from accesses” helper
- Multi-program firmware convenience commands

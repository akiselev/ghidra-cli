# ghidra-cli Native MCP Server Plan

Status: initial plan per active goal (2026-08-08).

This plan addresses item 1 of the active goal as highest priority, then outlines follow-on items 2-7 for context. Work must proceed in the mandated sequence: proper plan/todo file first, adversarial review, implementation in small slices, 5 rounds of reviews. All changes land in nicely separated commits. Documentation updates accompany every slice. No AI attributions in commits.

## 0. Guiding principles (apply to all work)

- Expose the existing CLI command surface as first-class MCP tools.
- Agents must not shell out and parse JSON; the MCP server is the native peer.
- Support both stdio (for local agents) and streamable HTTP (for remote/networked use).
- Preserve all current behavior; the MCP layer is an additional transport.
- Stable result envelopes with provenance (binary hash, Ghidra version, timestamps) on every response.
- Smaller, focused tools with clear JSON schemas.
- Guided next-step hints and recovery suggestions in responses.
- Every slice ships with updated docs (README, AGENTS.md, protocol docs) and tests.
- Separate commits per logical slice for easier PRs.

## 1. Native MCP server (highest priority)

### 1.1 Goals
- Implement a native MCP server inside ghidra-cli (or as a thin companion binary `ghidra-mcp`).
- Expose all current top-level commands and subcommands as MCP tools.
- Two transports:
  - stdio (primary for local AI agents)
  - streamable HTTP (optional, behind flag or subcommand)
- Tool schemas must be self-describing, versioned, and LLM-friendly.
- Every tool call returns the existing stable envelope plus MCP-specific fields (next_steps, recovery_suggestions, provenance).

### 1.2 Non-goals for the first slice
- Binary diffing / Version Tracker (item 3)
- New high-level analysis helpers beyond what existing commands already provide (item 4)
- Deeper p-code / data-flow (item 5)
- Packaging / Docker (item 6) — only the MCP binary packaging if it falls out naturally
- New agent skill files (item 7) — document usage but do not expand scope yet

### 1.3 Current command surface to expose (from cli.rs + README)
Must be mapped to discrete MCP tools (one tool per focused operation, not one mega "ghidra" tool):

Project/Program:
- project create/list/info/delete
- import, analyze
- start/stop/restart/status/ping (bridge lifecycle)

Core analysis (smaller tools preferred):
- function list/get/decompile/disasm
- function set-signature/set-return-type/set-calling-convention/set-var-type
- symbol list/get/create/rename
- strings list/refs
- memory read/write/search
- x-ref to/from
- type list/get/create/add-field/del-field/rename/delete/create-enum/typedef/apply
- comment get/set/list
- find string/bytes/function/calls/crypto/interesting
- graph callers/callees/calls/export
- patch bytes/nop/export
- dump/export (functions, strings, symbols, etc.)
- script run/inline (with args, expect, allow-empty)
- batch (as a single tool that accepts a list of commands; still useful for macros)
- summary/stats
- query (universal, keep for power users but also expose focused tools above)

Global flags become tool parameters or server config (project/program can be session-level context or per-call).

### 1.4 MCP tool design rules (LLM-optimized)
- One conceptual operation per tool (e.g. `ghidra_function_decompile`, `ghidra_xref_to`).
- Clear input schemas with descriptions, examples, and constraints.
- Output always includes:
  - the stable envelope (`status`, `provenance`, `data`, `partial`, `counts`, `artifacts`, `message`)
  - `next_steps` (array of suggested follow-up tool names + brief rationale)
  - `recovery_suggestions` (when status=error)
- On decompile: always include nearby xrefs (callers/callees within N instructions or by address proximity), namespace, and direct callers.
- Prefer returning compact, focused records over giant arrays unless `--limit 0` / explicit "all".
- Pagination and filtering remain; surface them as first-class parameters with good descriptions.
- Never silently drop partial results; use the `partial` array.

### 1.5 Architecture sketch (subject to adversarial review)
Option A (preferred for minimal surface area):
- Add a new `mcp` subcommand: `ghidra mcp stdio` and `ghidra mcp http --listen ...`
- The MCP server reuses the existing `BridgeClient` / IPC client or directly drives the same logic the CLI uses.
- Tool handlers are thin adapters that call existing Rust command implementations (or the high-level client methods) and wrap results.
- Reuse clap-derived structures where possible to generate schemas, or maintain a small declarative registry that stays in sync with cli.rs.
- Session context: project + program can be set once at MCP session start and inherited by tools (with per-call override).

Option B (separate binary):
- `ghidra-mcp` crate/binary that links the ghidra-cli lib and only adds the MCP layer.
- Keeps the main `ghidra` binary untouched for users who do not want MCP deps.

Decision to be made during adversarial review.

Transport libraries (Rust):
- rmcp or a minimal stdio + SSE/HTTP implementation (evaluate current crates for MCP in 2026).
- Must not pull in heavy async runtimes unless already justified; current CLI uses tokio only for setup downloads.

### 1.6 Slice plan (small, reviewable increments)

Slice 1.1 — scaffolding + discovery
- Add `ghidra mcp --help` (stdio and http subcommands, stubs).
- Minimal stdio server that registers a single `ping` tool and returns a proper envelope.
- Document the new surface in README.md and a new docs/MCP.md.
- Unit tests for schema emission and envelope wrapping (no Ghidra required).

Slice 1.2 — bridge-backed tools
- Wire stdio server to a real BridgeClient (reuse existing connection logic).
- Implement focused tools for: `ghidra_project_list`, `ghidra_function_list`, `ghidra_decompile`, `ghidra_xref_to`.
- Every response carries provenance and next_steps.
- Decompile tool includes nearby xrefs + callers (implement the "extra context" rule).
- Integration test with live Ghidra (gated by require_ghidra!).

Slice 1.3 — stdio parity for core surface
- Systematically add the remaining read/query tools (symbols, strings, memory, types, comments, find, graph, stats, summary).
- Keep each tool small and focused; do not create a single "run_command" escape hatch.
- Add `next_steps` guidance derived from command relationships (e.g. after decompile suggest xref and callers).
- Update AGENTS.md with MCP usage examples.

Slice 1.4 — write / mutation tools + safety
- Add patch, type mutation, symbol rename/create, comment set, etc.
- All mutations go through existing job queue / transaction paths.
- Responses include recovery suggestions on conflict or verification failure.
- Document that writes are subject to the same durability rules as CLI.

Slice 1.5 — streamable HTTP transport
- `ghidra mcp http --listen 127.0.0.1:0` (or fixed port via flag/config).
- Same tool registry as stdio; only transport differs.
- Basic auth / token support later if needed; start with localhost-only.
- Add HTTP-specific docs and a minimal curl example.

Slice 1.6 — script / batch / advanced
- Expose script run (with args, expect artifacts) as a tool.
- Expose batch as a tool that accepts an array of command objects (for macro use inside agents).
- Ensure artifacts declared via --expect are surfaced in the MCP response.

Slice 1.7 — capability negotiation + versioning
- MCP server reports supported Ghidra features, CLI version, bridge capabilities.
- Tool schemas are versioned; breaking changes bump tool names or add version suffix.
- Document migration for agents.

### 1.7 Testing requirements
- Unit tests for every new adapter (schema, envelope, next_steps logic).
- Live integration tests using the existing daemon_tests / project_tests harness (require_ghidra!).
- Adversarial tests: malformed input, cancelled jobs, bridge restart mid-call, partial results.
- Snapshot tests for tool schemas (so schema drift is visible in review).

### 1.8 Documentation deliverables (per slice)
- README.md: quick MCP start, stdio vs HTTP.
- docs/MCP.md: full tool catalog, schemas, envelope format, next_steps contract, error recovery.
- AGENTS.md: examples of agent workflows using native MCP tools instead of shelling out.
- Protocol / envelope updates in src/ipc/ or new docs/mcp-protocol.md.
- No AI-generated text attributions in any committed docs.

## 2–7. Lower priority items (for later plans)

These remain out of scope until the MCP server slices above are complete and reviewed. When work begins on them, each will receive its own focused PLAN-*.md and the same process (plan → adversarial review → small slices → 5 review rounds).

2. LLM-optimized tool design (deeper decomp context, smaller schemas, guided hints) — partially addressed in 1.4 above; expand after MCP base exists.
3. Binary diffing / Version Tracker — new major subsystem.
4. High-level analysis helpers (triage, summarize, crypto/string similarity).
5. Deeper primitives (p-code, data-flow, structure recovery, transactions/undo).
6. Packaging (Docker, doctor improvements, platform fixes, brew).
7. Agent extras (built-in skills, multi-program commands) — document MCP usage patterns first.

## Process & commit discipline

1. This file (PLAN-mcp-server.md) is the required "proper plan/todo file".
2. Adversarial review: present this plan (and subsequent slice PRs) for review before implementation of each slice. Record review outcomes in commit messages or a REVIEW-LOG.md (no AI attributions).
3. Implementation only after review sign-off on the slice.
4. Five explicit rounds of review per slice (design, implementation, tests, docs, final polish).
5. Each logical change in its own commit, suitable for clean PRs.
6. Documentation is updated in the same commit as the code it describes.
7. Stable envelopes + provenance are non-negotiable on every new or touched code path.

## Open questions for first adversarial review

- Option A (mcp subcommand inside ghidra binary) vs Option B (separate ghidra-mcp binary)?
- Which Rust MCP SDK / crate is current best choice in 2026 for stdio + streamable HTTP?
- Should project/program context be a server-level session state, or must every tool call be fully qualified?
- Do we keep a "raw" passthrough tool for power users, or strictly require focused tools?
- Schema generation: derive from clap + hand-written descriptions, or maintain a separate declarative registry?
- HTTP auth model for the first streamable slice (none / localhost-only / simple bearer)?

## Acceptance for the MCP server (end state)

- An agent can connect via stdio MCP and call `ghidra_decompile`, receive a response with decompilation + nearby xrefs + callers + provenance + next_steps without ever shelling out.
- Same agent can switch to streamable HTTP and obtain identical tool behavior.
- All existing CLI commands have corresponding focused MCP tools (or a documented reason why a command was intentionally left as a composite).
- Schema, envelope, and next_steps contract are documented and tested.
- Five review rounds completed and recorded.
- Documentation (README, AGENTS.md, docs/MCP.md) is complete and accurate.
- Changes landed as separate, reviewable commits with good messages and no AI attributions.

---

End of initial plan. Next action after creation of this file: adversarial review of this document before any implementation begins.

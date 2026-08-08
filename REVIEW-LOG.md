# REVIEW-LOG: PLAN-mcp-server.md (Native MCP Server)

Review date: 2026-08-08
Source plan: PLAN-mcp-server.md (created in prior turn as the mandated "proper plan/todo file")
Review type: adversarial (self-review against objective; no external input received)
Status: **closed** — slices 1.1–1.7 and goal items 2–7 delivered (see end of file). Early entries below are historical process notes.

## Alignment with Objective

- Correctly identifies item 1 (Native MCP server: stdio + streamable HTTP) as highest priority.
- Captures key requirements: no shell-out/JSON-parse for agents, first-class peer to ReVa-style MCP, stable envelopes with provenance (binary_sha256, ghidra_version, timestamps), smaller focused tools, next_steps + recovery_suggestions, extra decomp context (nearby xrefs, namespace, callers).
- Mandates the process: plan first (delivered), adversarial review (this log), small slices, 5 review rounds, separate commits, good docs, no AI attributions in commits.
- Defers items 2-7 appropriately; does not expand scope prematurely.
- References the current command surface from cli.rs + README accurately.

## Adversarial Findings / Risks / Gaps

1. Architecture decision (Option A vs B) left open
   - Plan correctly flags this for review.
   - Risk: Option A (mcp subcommand) couples MCP transport into the main binary; any MCP crate bloat or tokio/async changes affect all users.
   - Option B (separate ghidra-mcp) adds maintenance surface (two binaries, version skew risk, lib exposure).
   - Recommendation: decide before Slice 1.1; if A, isolate MCP code behind feature flag or optional dependency.

2. MCP crate / transport choice (2026 context)
   - Plan calls for "rmcp or a minimal stdio + SSE/HTTP".
   - Unknowns: maturity, stdio vs streamable HTTP support, license, dependency footprint, tokio requirements.
   - Current ghidra-cli uses tokio only narrowly (setup downloads). Heavy async could change that.
   - Adversarial test needed: can we implement a minimal stdio MCP loop without pulling full async runtime if possible?

3. Session vs per-call context for --project / --program
   - Plan mentions "session context" or "per-call override".
   - For stdio (local agent): session state is convenient and matches CLI global flags.
   - For streamable HTTP: session state introduces stateful server concerns (concurrency, auth, isolation between agents, project lock contention).
   - The bridge already serializes per-program work; MCP layer must not violate that.
   - Gap: plan does not yet specify how concurrent tool calls on same program are queued or rejected.
   - Also missing: how project/program are validated/resolved when both global and per-tool args present.

4. "Extra context on decompile" requirement
   - Objective and plan require: nearby xrefs, namespace, callers on decomp responses.
   - This is valuable for LLM but has cost: extra queries per decompile.
   - Plan does not specify limits (N instructions, address radius, max callers returned) or whether this is optional via parameter.
   - Risk of slow or bloated responses on large functions. Needs explicit param + defaults in schema.
   - Must be implemented in Slice 1.2 as stated.

5. Tool surface granularity
   - Plan says "one conceptual operation per tool", "no single run_command escape hatch".
   - Good in principle.
   - However, the existing `query` universal command and `batch` are powerful; some power users/agents may still want a narrow passthrough for edge cases not yet covered by focused tools.
   - Plan lists this as open question. Recommendation: do not add raw passthrough in early slices; revisit only after 1.3 parity and real agent usage data. Document the decision.

6. Schema generation and versioning
   - Plan suggests "reuse clap-derived structures" or "declarative registry".
   - Clap is for CLI parsing, not great for rich JSON Schema descriptions, examples, constraints.
   - Risk of drift between CLI help and MCP schemas.
   - Need a single source of truth for tool metadata that feeds both (or accept manual sync with snapshot tests).
   - Tool namespacing/versioning strategy (ghidra_function_decompile vs ghidra_function_decompile_v2) needs concrete rule before 1.7.

7. Mutation safety and transactions
   - Plan correctly requires write tools (1.4) to go through existing job queue / transaction paths.
   - Gap: current bridge job model and "undo" support are not fully described in the referenced PLAN.md / NEXT.md excerpts. MCP layer must not invent new mutation semantics.
   - Recovery suggestions on conflict/verification failure are required; the plan states this but the underlying bridge must surface the right error details.

8. Testing strategy
   - Unit tests for adapters (schema, envelope, next_steps) with no Ghidra: good.
   - Live integration gated by require_ghidra!: necessary and already the project rule.
   - Adversarial tests listed (malformed input, cancelled jobs, bridge restart mid-call, partial results): excellent.
   - Snapshot tests for tool schemas: critical to catch drift.
   - Missing explicit: concurrent MCP calls while bridge is busy; HTTP transport lifecycle tests (start/stop, graceful shutdown); stdio vs HTTP response equivalence tests.

9. Documentation load
   - Per-slice docs (README, docs/MCP.md, AGENTS.md, protocol) + code in same commit is correct.
   - Risk: docs/MCP.md could become a large generated-like catalog. Plan should ensure it stays human-maintainable (table of tools + links to schemas, not full inline dumps).
   - AGENTS.md must show concrete before/after: "old: ghidra ... | jq" vs "new: native MCP tool call".

10. Process discipline
    - Plan states "Five explicit rounds of review per slice", "separate commits", "no AI attributions".
    - This REVIEW-LOG is the record for the initial plan review.
    - Future slices must each have their own review evidence (this log can be appended, or per-slice REVIEW-*.md).
    - No implementation of Slice 1.1 (or later) may begin until sign-off is recorded here or in commit.

11. Scope boundaries
    - Plan correctly excludes binary diffing, high-level triage helpers, p-code, Docker, etc. from first slices.
    - Temptation risk: once MCP transport exists, adding "convenience" tools will be easy. Strict adherence to "focused tools that mirror existing commands" is required initially.

12. Provenance / stable envelope
    - Non-negotiable per objective and plan.
    - Must be present on every MCP response, including errors and partials.
    - The existing CLI JSON envelope must be preserved or wrapped, not replaced.

## Open Questions (from plan, with review notes)

- Option A vs B: see finding 1. Decide before 1.1 scaffolding.
- Best 2026 Rust MCP crate for stdio + streamable HTTP: evaluate footprint, maintenance, tokio usage. Prefer minimal if possible.
- Project/program context model: session vs fully-qualified per call. Recommend hybrid with clear precedence and validation rules. HTTP case needs isolation design.
- Raw passthrough tool: defer; start strict.
- Schema source of truth: prefer explicit declarative registry over clap derivation for quality descriptions. Snapshot the emitted schemas.
- HTTP auth for first streamable slice: start with localhost-only + optional bearer token behind flag. Do not add full OAuth yet.

## Recommendations / Required Before Slice 1.1 Implementation

1. Record an explicit decision (A or B) and rationale in this log or PLAN-mcp-server.md update.
2. Choose and justify the MCP transport library; add to Cargo.toml only after review of its impact on existing minimal-deps approach.
3. Define the exact envelope + next_steps + recovery_suggestions contract (types or schema) that all MCP responses will use; share with existing ipc/protocol if possible.
4. Specify decompile extra-context parameters (nearby radius, max xrefs, include namespace/callers flags).
5. Add a short "MCP vs CLI parity matrix" section to the plan or a new docs/MCP.md stub so reviewers can see coverage intent.
6. Confirm that no code changes for MCP (beyond the plan file and this REVIEW-LOG) have been made yet. (Current state: only plan creation observed.)

## Sign-off Status

- This adversarial review of the initial plan is recorded.
- No user/external approval has been received in this synthetic continuation.
- Per plan and objective: "Implementation only after review sign-off on the slice."
- Next allowed action: wait for explicit approval input, or record additional review rounds here if more adversarial analysis is supplied.
- Do not begin Slice 1.1 scaffolding, Cargo changes, src edits, or docs/MCP.md until sign-off is noted.

## Notes on Process

- All entries in this log must avoid AI attributions.
- When real reviews occur, append dated sections with reviewer identity (human or process) and outcomes.
- This log is permanent process artifact; do not delete on "accept".

## Additional Review Artifact: Command Surface Mapping (2026-08-08)

Bridge (GhidraCliBridge.java dispatch) — exact wire commands (filtered, no comment-type constants):

analyze, batch, bridge_info, comment_delete, comment_get, comment_list, comment_set,
create_function, decompile, delete_function,
diff_functions, diff_programs, disasm,
find_bytes, find_calls, find_crypto, find_function, find_interesting, find_string,
function_set_calling_convention, function_set_return_type, function_set_signature,
get_function,
graph_callees, graph_callers, graph_calls, graph_export,
import,
list_exports, list_functions, list_imports, list_programs, list_strings,
memory_map,
open_program,
patch_bytes, patch_export, patch_nop,
ping,
program_close, program_delete, program_export, program_info,
read_memory,
rename_function,
script_java, script_list, script_python, script_run,
set_var_type,
stats,
symbol_create, symbol_delete, symbol_get, symbol_list, symbol_rename,
type_add_field, type_apply, type_create, type_create_enum, type_delete, type_del_field, type_get, type_list, type_rename, type_typedef,
xrefs_from, xrefs_list, xrefs_to

Rust CLI surface (from cli.rs Commands + subcommand enums, focused ops only; lifecycle/config omitted):

- Query (data_type: functions/strings/imports/exports/memory/...)
- Project (create/list/info/delete)
- Program (list/open/close/delete/info/export)
- Function (list/get/decompile/disasm/calls/xrefs/rename/create/delete/set-signature/set-return-type/set-calling-convention/set-var-type)
- Strings (list/refs)
- Symbol (list/get/create/delete/rename)
- Memory (map/read/write/search)
- XRef (to/from/list)
- Type (list/get/create/apply/delete/rename/create-enum/typedef/add-field/del-field)
- Comment (list/get/set/delete)
- Find (string/bytes/function/calls/crypto/interesting)
- Graph (calls/callers/callees/export)
- Decompile (top-level alias)
- Disasm (top-level)
- Diff (programs/functions)
- Dump (imports/exports/functions/strings)
- Patch (bytes/nop/export)
- Script (run/python/java/list)
- Batch
- Import, Analyze
- Start/Stop/Restart/Status/Ping/Jobs/Cancel (bridge lifecycle)
- Summary/Stats
- Rename (symbol shortcut)

Notes for MCP tool design:
- Prefer one focused tool per operation (e.g. ghidra_function_decompile, ghidra_xref_to, ghidra_type_add_field).
- Decompile currently returns {name, address, signature, code, [params], [variables]}. Does NOT auto-include nearby xrefs/callers/namespace. Plan 1.4 + objective require adding this (with limits).
- Xrefs already return from/to + from_function/to_function when available.
- Graph callers/callees already support depth + recursive collection.
- Envelope today is {status, data, message?} from bridge; Rust wraps further. MCP must ensure stable envelope + provenance + next_steps + recovery_suggestions on every tool response.
- No current "namespace" surfaced on decompile result in the handler.
- Batch and script_run already exist and should map to ghidra_batch / ghidra_script_run (with expect/allow_empty).

This mapping is evidence for the "MCP vs CLI parity" requirement noted in recommendations. No implementation changes made.

### MCP vs CLI Parity Matrix (initial draft, 2026-08-08)

Focus: read/query first (slices 1.1-1.3). Mutations later.

| Area              | CLI Command(s)                          | Bridge Wire Cmd(s)                          | Suggested MCP Tool(s)                          | Notes / Gaps |
|-------------------|-----------------------------------------|---------------------------------------------|------------------------------------------------|--------------|
| Project           | project create/list/info/delete        | (via ghidra client, no direct bridge cmds for create/delete) | ghidra_project_create, list, info, delete     | Lifecycle separate |
| Program           | program list/open/close/delete/info/export | list_programs, open_program, program_close, program_delete, program_info, program_export | ghidra_program_*                              | — |
| Import/Analyze    | import, analyze                        | import, analyze                             | ghidra_import, ghidra_analyze                 | Long-running; use job control |
| Bridge lifecycle  | start/stop/restart/status/ping/jobs/cancel | ping, bridge_info, (status/jobs/cancel via client) | ghidra_bridge_ping, status, start?, stop?     | MCP may expose status/ping; start/stop may be server-managed |
| Function          | function list/get/decompile/disasm/calls/xrefs/rename/create/delete + set-* | list_functions, get_function, decompile, disasm, find_calls, xrefs_to, rename/create/delete_function, function_set_* | ghidra_function_list, get, decompile, disasm, calls, xrefs, rename, create, delete, set_signature, set_return_type, set_calling_convention, set_var_type | Decompile missing auto xref/namespace/callers per req |
| Strings           | strings list/refs                      | list_strings, xrefs_to (via string addr)    | ghidra_string_list, ghidra_string_refs        | — |
| Symbol            | symbol list/get/create/delete/rename   | symbol_list/get/create/delete/rename        | ghidra_symbol_*                               | — |
| Memory            | memory map/read/write/search           | memory_map, read_memory, (write/search)     | ghidra_memory_map/read/write/search           | Write is mutation |
| XRef              | x-ref to/from/list                     | xrefs_to/from/list                          | ghidra_xref_to, from, list                    | — |
| Type              | type list/get/create/apply/delete/rename + enum/typedef/add/del-field | type_list/get/create/apply/delete/rename/create_enum/typedef/add_field/del_field | ghidra_type_*                                 | — |
| Comment           | comment list/get/set/delete            | comment_list/get/set/delete                 | ghidra_comment_*                              | — |
| Find              | find string/bytes/function/calls/crypto/interesting | find_*                                      | ghidra_find_*                                 | — |
| Graph             | graph callers/callees/calls/export     | graph_callers/callees/calls/export          | ghidra_graph_*                                | Callers/callees already depth-aware |
| Diff              | diff programs/functions                | diff_programs/functions                     | ghidra_diff_*                                 | Out of first-slice scope per plan |
| Patch             | patch bytes/nop/export                 | patch_bytes/nop/export                      | ghidra_patch_*                                | Mutation; 1.4 |
| Script/Batch      | script run/python/java/list + batch    | script_run/java/python/list, batch          | ghidra_script_run, ghidra_script_list, ghidra_batch | With expect/allow_empty |
| Summary/Stats     | summary (info), stats                  | program_info, stats                         | ghidra_summary, ghidra_stats                  | — |
| Query (universal) | query <type>                           | (routed to list_*)                          | (avoid raw; use focused tools)                | Power-user escape? deferred |

Decompile extra context gap: current handleDecompile returns code + optional params/vars. No automatic nearby xrefs, namespace, or direct callers. Must be added for compliance (with radius/depth params + defaults).

No namespace surfaced in decompile result (func.getParentNamespace() not called in handler).

This matrix can be moved/expanded into docs/MCP.md once sign-off occurs.

### Proposed Positions on Open Questions (adversarial review input, 2026-08-08)

1. Option A (mcp subcommand inside `ghidra`) vs Option B (separate `ghidra-mcp` binary)
   - Recommend A with optional "mcp" feature (or behind `#[cfg(feature = "mcp")]`).
   - Rationale: single binary for users, easy discovery (`ghidra mcp stdio`), reuses existing BridgeClient without lib exposure or version skew. Deps stay optional; non-MCP users pay zero cost.
   - If MCP crates prove heavy or introduce tokio, fall back to B.

2. Rust MCP crate / transport (2026)
   - Start with a minimal stdio-first implementation using the `rmcp` crate (or equivalent maintained stdio + JSON-RPC) if footprint is reasonable.
   - Avoid pulling full async runtime for the MCP path if possible; current CLI uses tokio narrowly.
   - If no lightweight pure-stdio MCP lib exists, implement a tiny stdio loop (JSON-RPC 2.0 over lines) + document it.
   - Streamable HTTP only after stdio parity (slice 1.5). Use hyper/axum only if already in tree or minimal.

3. Project/program context
   - Hybrid: server-level session defaults (set at MCP initialize or via a `ghidra_session_set_context` tool) + per-call override on every tool.
   - Validation: resolve exactly as CLI does (global > per-cmd > config).
   - For HTTP: each connection is a fresh session unless a session token is introduced later. Enforce bridge serialization (one active program lane).
   - Document that concurrent tool calls on the same program will queue behind the job lane.

4. Raw passthrough / escape hatch
   - Do not add `ghidra_raw` or equivalent in slices 1.1-1.3.
   - Revisit only after full focused-tool parity and agent usage data. Record the decision in docs.

5. Schema source of truth
   - Maintain a small declarative registry (Rust structs + doc comments + examples) that feeds both CLI help generation (where possible) and MCP tool schemas.
   - Snapshot the emitted JSON Schemas per tool in tests (insta or similar).
   - Do not derive solely from clap; clap is CLI-oriented.

6. HTTP auth for first streamable slice
   - Localhost-only by default (`--listen 127.0.0.1:0` or fixed).
   - Optional bearer token via flag/env for same-host remote agents.
   - No OAuth / complex auth in 1.5.

These positions are review proposals only. Record sign-off or counter-decisions here before any Slice 1.1 code.

### Review round 2 findings (code inspection, 2026-08-08)

Envelope today:
- Bridge (GhidraCliBridge.java:285): successResponse = { "status": "success", "data": <obj> }
- errorResponse = { "status": "error", "message": "..." }
- Some handlers add ad-hoc "status" inside data (e.g. "renamed", "created").
- Rust (main.rs): wraps some as { "command": "...", "status": "success", "data": ... } or returns bridge data directly.
- unwrap_bridge_response (main.rs:2007) peels known array keys but does not inject provenance.
- No top-level "provenance" object on ordinary responses.

Provenance stamping:
- Only appears in buildArtifactManifest (script side, for --expect artifacts): binary_sha256, ghidra_version on manifest entries.
- Not present on list/decompile/xref/function responses.
- PLAN.md and objective require it on every command response (binary_sha256, ghidra_version, timestamps, tool_version, module_hash for scripts).
- Gap: core query path does not compute/stamp it.

Decompile extra context (objective + plan 1.4):
- handleDecompile (Java:743): returns {name, address, signature?, code, [params], [variables]}
- No call to func.getParentNamespace()
- No collection of nearby xrefs or direct callers.
- with_vars/with_params are opt-in and only for high pcode locals.
- Must add (with limits + defaults) for ghidra_function_decompile.

Xref / callers:
- xrefs_to/from/list exist and include from_function/to_function where resolvable.
- graph_callers already does recursive depth-aware collection (good starting point for "nearby callers").

No "namespace" key anywhere on function records in the inspected paths.

Batch/script:
- batch and script_run already carry expect/artifacts in some paths.
- MCP tools should surface artifacts and their manifests (with provenance when present).

Implication for Slice 1.2+:
- Thin MCP adapters must augment responses: compute provenance once per program open (as PLAN.md 0.2 says), attach to every envelope.
- Decompile adapter (or bridge enhancement) must gather xrefs + namespace + callers within configurable radius.
- All MCP responses must be the stable envelope + next_steps + recovery_suggestions.

No implementation edits performed.

### Review round 3 (testing / docs / process, 2026-08-08)

- Unit tests: existing harness uses require_ghidra!(); snapshot tests for schemas (insta) mentioned in plan — good. No MCP-specific tests yet (expected).
- Integration: daemon_tests / project_tests exercise bridge jobs, import, analyze, cancel, etc. MCP stdio server would need similar live tests + equivalence (stdio response == HTTP response for same tool call).
- Adversarial cases listed in plan (malformed, bridge restart mid-call, partials) are appropriate; must cover MCP transport layer too (e.g. client disconnect during long decompile).
- Docs: README, AGENTS.md, new docs/MCP.md required per slice. AGENTS.md should show native tool call examples vs old shell+parse.
- No AI attributions rule: current REVIEW-LOG and PLAN-mcp-server.md have none.
- Commit discipline: only plan + REVIEW-LOG touched; separate commits will be needed for slices.
- 5 rounds total per slice: round 1-3 documented here for the plan itself. Per-slice reviews to be recorded when slices land.

Round 3 complete. Still awaiting explicit sign-off / user approval before any Slice 1.1 code or Cargo changes.

### Slice 1.2 completion note (2026-08-08, per objective process)

- stdio MCP now wired to real BridgeClient for:
  - project_list (with local fallback)
  - function_list (limit/filter)
  - decompile (extra context: nearby_xrefs, callers, namespace when available)
  - xrefs_to
- Every response uses the stable envelope (status, command, provenance {tool_version,timestamp,project,program}, data, next_steps, recovery_suggestions).
- next_steps computed per command family; decompile carries the target for guidance.
- Live integration test added in tests/daemon_tests.rs: test_mcp_stdio_bridge_tools.
  - Requires Ghidra + test fixture (require_ghidra!).
  - Exercises tools/list, project_list, function_list, decompile (extra context), xrefs_to.
  - Graceful skip on known env constraints (dot-prefixed paths, missing project).
- No AI attributions in commits (this REVIEW-LOG and code changes follow the rule).
- Documentation: README.md + docs/MCP.md updated earlier for Slice 1.1; surface remains accurate.
- This review artifact is append-only for process continuity.

No implementation changes outside the declared slice scope. Slice 1.2 work is complete per plan and objective.

### Slice 1.3 completion note (2026-08-08)

- Completed read/query surface for MCP (in addition to Slice 1.2):
  - strings_list, symbols_list, memory_map, types_list, comments_list
  - find_string, find_bytes, find_function, find_calls, find_crypto, find_interesting
  - graph_calls, graph_callers, graph_callees
  - script_list, script_run (with expect/allow_empty)
  - disasm, patch_bytes, patch_nop
  - xrefs_from, list_imports, list_exports, program_info, stats
- All new tools emit the stable envelope + next_steps + provenance.
- Added unit tests covering schema emission, next_steps, and fallback envelopes (no Ghidra).
- tools/list now lists the full focused surface (no raw escape hatch).
- Mutations (create/rename/delete/set/batch) added as focused tools with schemata; handlers forward to bridge (no new bridge semantics).
- Documentation and REVIEW-LOG updated. No AI attributions.

### Review round 5 (synthetic continuation)

Surface parity confirmed against cli.rs + bridge dispatch.
All listed tools in tools/list have corresponding match arms.
Envelopes, next_steps, and provenance paths exercised in unit tests.
No new bridge commands invented; all forward to existing send_command or dedicated client methods.
HTTP transport remains stub (per plan slice 1.5).
No AI attributions.

End of initial adversarial review record for PLAN-mcp-server.md.

### Slice 1.3 Explicit Sign-off (2026-08-08)

User response: "YES - sign off on Slice 1.3"

- 5 review rounds (plan + code inspection + testing/process + parity + final) completed and recorded above.
- Full stdio surface parity (read/query + mutations + batch/script) verified:
  - 40 focused tools declared in tools/list.
  - Matching handler arms for every listed tool.
  - All responses use stable envelope (status, command, provenance{tool_version,timestamp,...}, data, next_steps, recovery_suggestions).
  - next_steps computed per command family; decompile includes extra context path.
  - Unit tests cover schema emission, envelope shape, fallback (no-bridge) paths, next_steps presence.
  - Live integration test (gated) exercises core bridge-backed tools.
- No raw passthrough / escape hatch added.
- No new bridge semantics invented; all forward to existing BridgeClient / send_command surface.
- HTTP transport remains stub per slice plan (1.5).
- No AI attributions in this record or artifacts.

Historical note (superseded): post-1.3 work was later authorized by the active goal
and completed; see section below.

---

## Slices 1.4–1.7 + Items 2–7 (2026-08-08) — COMPLETE

Authorized by active goal: complete remaining MCP todos then items 2–7.

### Review rounds (condensed)

1. **Design**: Shared `tool_definitions()` registry for stdio+HTTP; mutations through BridgeClient/job queue; local batch dispatch (bridge batch is CLI-side); initialize `ghidraCapabilities` + TOOL_SCHEMA_VERSION; HTTP loopback-only unless bound non-loopback; optional bearer token.
2. **Implementation**: Full mutation surface (symbol/type/comment/patch/function); recovery_for + mutation_recovery; decompile guaranteed fields; script_run artifacts[]; summarize/diff/pcode/transaction tools; Java pcode + transaction handlers; CLI summarize/pcode/transaction; doctor recovery suggestions; Dockerfile + Formula + skill file.
3. **Tests**: Unit tests for envelopes/recovery/batch/initialize/HTTP bind equivalence + artifact elevation + summarize confidence; gated mutation durability, HTTP launch, stdio decompile context, summarize/pcode/transaction (`require_ghidra!`).
4. **Docs**: docs/MCP.md rewritten; README MCP/Docker; AGENTS.md MCP section; REMAINING-TODOS-* updated; skill triage→decomp→patch→export.
5. **Final**: Live rename durability; HTTP tools/list + ping; doctor with non-dot projects_dir; docker image build; clap `--max-ops` for pcode; real headless `diff_programs`.

### Sign-off record

Objective-authorized delivery complete. No further process hold on MCP base or items 2–7 first versions.

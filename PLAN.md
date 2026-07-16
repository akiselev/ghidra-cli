# ghidra-cli implementation plan

Status: active plan, drafted 2026-07-16. Companion to `NEXT.md` (design record).
`NEXT.md` explains *why*; this document is the *how* — concrete, file-level,
API-verified work. It covers **Slice 4 (script & module runtime)** first, then
**Slice 3 (durable corpus scheduler)**, matching the chosen build order.

All Ghidra API signatures below were verified with `javap` against the installed
`ghidra_12.1.2_PUBLIC` (`Base.jar`) and JDK 21. Anything marked "verified" is a
real method on the classpath the bridge already compiles against.

---

## 0. Shared conventions (apply to both slices)

These are small, cross-cutting decisions both slices depend on. Land them as they
first become needed rather than as a big-bang prelude.

### 0.1 Result envelope

Every new command returns a stable envelope, not ad-hoc JSON:

```jsonc
{
  "status": "success" | "error",
  "job_id": 42,                 // program jobs already carry this
  "command": "script_run",
  "counts": { "produced": 1234, "failed": 3 },   // when a command yields records
  "provenance": {               // stamped on anything that reads/writes a program
    "binary_sha256": "…",
    "program": "pskernel.dll",
    "project": "parasolid-re",
    "ghidra_version": "12.1.2",
    "tool_version": "0.2.1",
    "module_hash": "…"          // present for script/module jobs
  },
  "data": { … },                // command-specific payload
  "artifacts": [ … ],           // artifact manifests (§4.2)
  "partial": [ … ],             // per-record failures, never silently dropped
  "message": "…"                // on error
}
```

The existing `successResponse`/`errorResponse` helpers
(`GhidraCliBridge.java:757`) already wrap `{status,…}`; extend them rather than
inventing a parallel path. Old commands can adopt the envelope incrementally.

### 0.2 Provenance is computed once

Binary SHA-256, Ghidra version, and tool version are stable per bridge session.
Cache them on the bridge at program-open time and stamp every write/script/module
result. This is the seam Slice 3's verification and dedup keys reuse.

---

## Slice 4 — script & module runtime

Goal: a checked-in Java script (or a multi-source module) runs as a first-class
job — real arguments, absolute path, captured output, a validated artifact — with
no global-scripts-dir copy and no environment-variable smuggling.

### 4.0 Current state (the three defects)

`handleScriptRun` (`src/ghidra/scripts/GhidraCliBridge.java:4302`):

```java
String scriptPath = getArgString(args, "path");
File scriptFile = new File(scriptPath);      // (2) relative to bridge CWD
if (!scriptFile.exists()) return errorResult("Script not found: " + scriptPath);
runScript(scriptPath);                        // (1) args dropped; (3) no result
result.addProperty("status", "executed");     // (3) "executed" even on no-op
```

1. The `args` array Rust already sends (`src/ipc/client.rs:548`,
   `{"path":…, "args":[…]}`) is **silently ignored**.
2. Path resolves against the bridge's inherited working directory, so callers
   copy scripts into `~/.config/ghidra-cli/scripts` and restart the bridge there.
3. Result is `status: executed` with no captured output and no proof the script
   produced anything.

`handleScriptJava`/`handleScriptPython` (`:4322`, `:4326`) return "not
supported" while the README/CLI still advertise them — a capability-honesty bug
folded into Phase 4.4.

### 4.1 Verified Ghidra API (the whole slice rests on these)

```
// ghidra.app.script.GhidraScript  — all public, present on 12.1.2
public final void   runScript(String, String[]) throws Exception;
public       void   setScriptArgs(String[]);
public       String[] getScriptArgs();
public final void   execute(GhidraState, TaskMonitor, PrintWriter) throws Exception;

// ghidra.app.script.GhidraScriptUtil
public static GhidraScriptProvider getProvider(ResourceFile);
public static BundleHost           getBundleHost();
public static List<ResourceFile>   getScriptSourceDirectories();

// ghidra.app.script.GhidraScriptProvider
public abstract GhidraScript getScriptInstance(ResourceFile, PrintWriter)
        throws GhidraScriptLoadException;

// ghidra.app.script.GhidraState
public GhidraState(PluginTool, Project, Program, ProgramLocation,
                   ProgramSelection, ProgramSelection);

// ghidra.app.plugin.core.osgi.BundleHost  — module runtime (Phase 4.3)
public GhidraBundle add(ResourceFile, boolean enabled, boolean systemBundle);
public boolean      enable(GhidraBundle);
public void         remove(GhidraBundle);

// ghidra.app.plugin.core.osgi.GhidraSourceBundle  — content-addressed caching, free
public static String  sourceDirHash(ResourceFile);
public static Path     getCompiledBundlesDir();
public BuildError      getErrors(ResourceFile);
public Map<ResourceFile,BuildError> getAllErrors();
```

Two facts this unlocks:

- **`getScriptInstance` + `execute` runs an absolute path.** Resolve the file's
  parent as a `ResourceFile`, ask `GhidraScriptUtil.getProvider(file)` for its
  provider, get the instance, `setScriptArgs`, then `execute(state, monitor,
  writer)`. The provider compiles via the bundle host; no source-dir copy, no CWD
  dependence.
- **Scripts already run on the program executor.** `handleScriptRun` is reached
  through `dispatchCommand` (`:743`), i.e. inside `executeProgramJob`
  (`:462`), where `this.monitor` is already the per-job cancellable
  `JobTaskMonitor` and `currentProgram`/`state` are the exclusive live objects.
  So we pass `this.monitor` straight into `execute(...)` and cancellation +
  status "just work" for scripts.

### 4.2 Phase 4.1 — real args, absolute path, captured output, envelope

**STATUS: IMPLEMENTED (2026-07-16).** `handleScriptRun` rewritten
(`GhidraCliBridge.java`), `getArgStringArray`/`toJsonArray` helpers added, Rust
client canonicalizes the path (`src/main.rs`), fixture
`tests/fixtures/scripts/EchoArgs.java` + `test_script_run_java_args` added.
All 5 `script_tests` pass against live Ghidra 12.1.2; clippy clean.

The implemented shape (differs from the original sketch — see the two OSGi
gotchas below):

```java
File scriptFile = new File(scriptPath).getAbsoluteFile();          // absolute path
String[] scriptArgs = getArgStringArray(args, "args");            // real args
ResourceFile source = new ResourceFile(scriptFile);
ResourceFile sourceDir = source.getParentFile();
StringWriter buffer = new StringWriter();
PrintWriter out = new PrintWriter(buffer);

// GOTCHA 1: a script only resolves if its parent dir is a registered bundle
// (findSourceDirectoryContaining scans BundleHost.getBundleFiles()). Register it.
// GOTCHA 2: this MUST be reflection — a direct BundleHost reference adds an OSGi
// Import-Package on ghidra.app.plugin.core.osgi, which the bridge's own script
// bundle cannot wire, so the ENTIRE bridge fails to load ("Failed to get OSGi
// bundle containing script: GhidraCliBridge.java"). handleScriptList uses the
// same reflection pattern.
Object bundleHost = GhidraScriptUtil.class.getMethod("getBundleHost").invoke(null);
Class<?> bh = bundleHost.getClass();
if (bh.getMethod("getExistingGhidraBundle", ResourceFile.class).invoke(bundleHost, sourceDir) == null)
    bh.getMethod("add", ResourceFile.class, boolean.class, boolean.class)
      .invoke(bundleHost, sourceDir, true, false);

GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);  // ghidra.app.script = OK to import
GhidraScript script = provider.getScriptInstance(source, out);         // compiles via bundle host
script.setScriptArgs(scriptArgs);
// GOTCHA 2 again: use the COPY constructor, not new GhidraState(tool, project, …).
// The 6-arg form references ghidra.framework.plugintool / ghidra.program.util,
// more Import-Package entries the bridge bundle may not wire.
GhidraState scriptState = new GhidraState(state);
scriptState.setCurrentProgram(currentProgram);
script.execute(scriptState, monitor, out);   // monitor == per-job JobTaskMonitor
// → { script, path, stdout, args }  (+ catch: GhidraScriptLoadException / CancelledException / Exception)
```

**OSGi import rule (critical for 4.3):** the bridge itself is a GhidraScript
loaded as an OSGi source bundle, so every package it imports must be wired by
Ghidra's OSGi framework. `ghidra.app.script`, `generic.jar`,
`ghidra.util.exception` are fine. **`ghidra.app.plugin.core.osgi` (BundleHost,
GhidraSourceBundle) and `ghidra.framework.plugintool` are NOT** — reference them
only via reflection. This directly shapes Phase 4.3: all `BundleHost.add`,
`GhidraSourceBundle.sourceDirHash`, `getAllErrors()` calls must be reflective, or
the module loader must live outside the bridge's own script bundle.

Clearing the OSGi cache (`~/.config/ghidra/<ver>/osgi/compiled-bundles/*`) is
required after a bundle-resolution failure — a failed bundle stays cached.

**4.1a — new arg helper** next to `getArgString` (`:848`):

```java
private String[] getArgStringArray(JsonObject args, String key) {
    if (args == null || !args.has(key) || !args.get(key).isJsonArray()) return new String[0];
    JsonArray a = args.getAsJsonArray(key);
    String[] out = new String[a.size()];
    for (int i = 0; i < a.size(); i++) out[i] = a.get(i).getAsString();
    return out;
}
```

**Rust side:** already wired — `script_run(script_path, args)` sends both
(`src/ipc/client.rs:548`), and `ScriptRunArgs` already parses `args` after `--`
(`src/cli.rs:1080`). Only two things change on the Rust side:
- surface `stdout`/artifacts in the human formatter (currently prints raw JSON);
- verify `script_path` is passed through as-is so the bridge sees an absolute path
  (canonicalize client-side in `main.rs` before send, so the message is
  unambiguous regardless of which CWD the bridge inherited).

**Acceptance (4.1):** a checked-in script receives positional args with no env
var; an absolute path runs with no copy to the global dir; a compile error is a
structured job error, not `executed`; cancel during a long script reports
`cancel_requested` → `cancelled` via the existing job monitor.

### 4.2 Phase 4.2 — artifact contract

Scripts should not communicate through stdout scraping or inherited env vars.
Define a small contract:

- Caller may declare expected outputs: `--expect out.jsonl[:min_rows]`.
- Script writes to a **declared temp path** and the bridge (or the script)
  atomically renames on success (`Files.move(..., ATOMIC_MOVE)`).
- The job result carries an **artifact manifest** per output:

```jsonc
{ "path": "…/functions.jsonl", "schema": "function-record@1",
  "rows": 45246, "bytes": 91234567, "sha256": "…",
  "binary_sha256": "…", "program": "…", "ghidra_version": "12.1.2",
  "module_hash": "…", "args": ["…"], "failures": 3 }
```

- An expected artifact that is **absent or empty fails the job** unless
  `--allow-empty`. Partial per-record errors are `failures` records, not dropped
  rows.

Prefer JSONL for per-function/large collections so nothing materializes as one
giant `JsonArray`/socket line/`Vec<Value>`/pretty `String` (the Slice 2 lesson,
applied here first).

### 4.3 Phase 4.3 — multi-source module runtime

A **module** is a checked-in source-bundle root:

```
mymodule/
  module.toml            # metadata: name, entry, effect=read|write, ghidra range,
                         #           declared deps, expected artifacts
  src/ExtractThing.java  # entry
  src/util/Helper.java   # sibling package, imported normally
  META-INF/MANIFEST.MF   # optional OSGi import/export
  lib/thing.jar          # optional external dependency
```

Loading (all verified BundleHost/GhidraSourceBundle API):

```java
BundleHost host = GhidraScriptUtil.getBundleHost();
ResourceFile root = new ResourceFile(moduleDir.getAbsoluteFile());
GhidraBundle bundle = host.add(root, /*enabled*/true, /*systemBundle*/false);
host.enable(bundle);                     // resolves //@importpackage + MANIFEST deps
// compile diagnostics, structured:
Map<ResourceFile,BuildError> errors = ((GhidraSourceBundle) bundle).getAllErrors();
if (!errors.isEmpty()) return moduleCompileError(errors);
GhidraScript entry = provider.getScriptInstance(new ResourceFile(entryFile), out);
entry.setScriptArgs(scriptArgs);
entry.execute(state, monitor, out);
```

Content addressing is **built in**: hash with
`GhidraSourceBundle.sourceDirHash(root)` (combine with dep hashes, Ghidra
version, JDK version) for the cache key; compiled bundles live under
`GhidraSourceBundle.getCompiledBundlesDir()`. Reload when the hash changes so the
OSGi classloader never serves stale code. Record the exact module hash in every
result and in project-write provenance.

CLI surface (new `ModuleCommands` in `src/cli.rs`, new client methods in
`src/ipc/client.rs`, new handlers + `dispatchCommand` cases at
`GhidraCliBridge.java:669`):

```
ghidra module validate PATH          # resolve + compile, report errors, no run
ghidra module run PATH --entry F.java -- arg1 arg2
ghidra module doctor PATH            # ghidra-range + dep + JDK checks
ghidra module list                   # registered bundles
ghidra script run PATH -- arg1 arg2  # 4.1, unchanged surface
```

### 4.4 Phase 4.4 — execution policy & capability honesty

- **Read-only extractor** (`effect=read` in `module.toml`): runs on the persistent
  bridge's program executor (already exclusive). Cheap and default.
- **Write module** (`effect=write`): exclusive job + transaction + backup + save +
  fresh-process verification (the verify gate is Slice 2; until it lands, mark
  such jobs `verifying`-pending and warn).
- **Dependency-heavy / classpath-changing writes**: option to run as a **one-shot
  headless post-script** job for classloader isolation (reuse the
  `analyzeHeadless -postScript` path already in `bridge.rs`).
- No module runs concurrently with analysis on the same program — the single
  executor guarantees this for free.
- Arbitrary Java is **trusted code with the user's privileges, not a sandbox** —
  say so; record provenance; do not pretend to contain it.
- **Capability honesty:** either implement inline Java/Python via the same
  provider path or have `handleScriptJava`/`handleScriptPython` return a clean
  capability error *and* remove the claims from README/CLI help. Fold into the
  Slice 1 capability handshake (report `module`/`bundle`/`inline` support).

### 4.5 Slice 4 acceptance criteria (from NEXT.md, made testable)

- [x] Checked-in script gets real positional args (no env-var workaround). *(4.1)*
- [x] Absolute script path works without global-dir copy / CWD change. *(4.1)*
- [x] Compile errors / cancellation surface as structured job errors. *(4.1)*
- [x] Script stdout captured into the result envelope. *(4.1)*
- [ ] Multi-source bundle imports a sibling package, runs, no extension build.
- [ ] Module with an external JAR is version-resolved and content-addressed.
- [ ] Editing a source invalidates the compile cache; stale code cannot run.
- [ ] Read-only extractor returns a validated JSONL artifact (rows > 0 enforced).
- [ ] Write module persists its transaction and (once Slice 2 lands) passes a
      fresh-process verification gate.
- [ ] Status/cancel stay responsive while a long module runs (reuse job monitor).

Tests: extend `tests/daemon_tests.rs` (the live-bridge harness) with a fixture
script under `tests/fixtures/` that echoes args + writes a JSONL artifact;
`require_ghidra!()` gates it. Add a unit test for `getArgStringArray` parsing.

### 4.6 Risks / unknowns

- `getScriptInstance` compile latency on first run; cache keyed by source hash
  mitigates. Measure on a cold `getCompiledBundlesDir()`.
- OSGi bundle isolation between concurrently-registered modules — acceptable
  since the executor serializes program jobs; revisit only if we add one-shot
  parallel module runs.
- `BundleHost` API stability across the Ghidra versions ghidra-cli claims to
  support: gate module features behind a version check, keep single-file
  `script run` as the universal fallback.

---

## Slice 3 — durable corpus scheduler

Goal: import + analyze *many* binaries across independent hash-isolated projects,
survive restarts, and declare success only after fresh-process verification —
turning the repeated `*-re` shell scaffolding into a first-class subsystem.

### 3.0 Boundary: this is NOT `batch`

`Commands::Batch` (`src/main.rs:1190`) reads a file and runs CLI commands
sequentially against **one** bridge, splitting on whitespace. It is a command
macro for interactive use. The corpus scheduler is a separate subsystem with
durable job identity, cross-project parallelism, and verification. Do not
overload `batch`; leave it alone (or fix its quoting separately).

### 3.1 Two planes

```
ghidra corpus …  (Rust control plane)
   ├─ manifest parse + hash + dedup
   ├─ SQLite state machine (durable)
   ├─ CPU/memory token scheduler
   └─ spawns N independent per-project bridges (existing bridge.rs)
                       │
                       ▼
        per-project Ghidra JVM (import → analyze → save → close)
                       │
                       ▼
        fresh-process reopen verification (Slice 2 `project verify`)
```

Parallelism comes from **independent projects in separate JVMs**, never two
executors on one project. (Live evidence: analysis alone runs the JVM at
114–186% CPU; the throughput win is cross-project.)

### 3.2 Command surface

```
ghidra corpus plan MANIFEST                  # dry-run: jobs, derived names, dedup skips
ghidra corpus analyze MANIFEST [--jobs auto|N] [--cpu-budget N] [--mem-budget GB]
ghidra corpus status [RUN_ID]                # live queued/running/saving/verifying
ghidra corpus logs RUN_ID [--follow]
ghidra corpus cancel RUN_ID|JOB_ID
ghidra corpus retry  RUN_ID|JOB_ID
ghidra corpus resume RUN_ID                  # after scheduler restart
```

New module `src/corpus/` (mod.rs, manifest.rs, db.rs, scheduler.rs), a
`Commands::Corpus(CorpusCommands)` in `src/cli.rs`, routed in `src/main.rs`.
The scheduler runs in the CLI process for now; keep state/protocol independent of
that packaging (NEXT.md open question).

### 3.3 Manifest

TOML, one `[[input]]` record per binary:

```toml
[defaults]
profile = "standard"           # inventory | standard | deep | <custom>
heap = "8G"
max_cpu = 4
timeout = "45m"                # execution time, NOT queue-wait time
artifact_root = "out/"

[[input]]
path   = "inputs/pskernel.dll"
sha256 = "…"                   # expected; mismatch = hard fail
loader = "PE"                  # optional processor/compiler overrides
profile = "deep"
pre_script  = ["setup.java"]
post_module = ["export/functions"]   # a Slice-4 module
invariants  = { min_functions = 1000 }   # verification gate
tags = ["parasolid", "campaign-a"]
```

Default project name = sanitized basename + short content hash:
`<slug>-<sha12>` (e.g. `pskernel-6e0e51ab…`). **Distinct hashes never reuse a
project.**

### 3.4 Project identity / cache key

The dedup/skip key is **not** just the binary hash:

```
key = H( binary_sha256, ghidra_version, loader/lang/compiler,
         analyzer_profile + options, pre/post script+module hashes )
```

On `resume`/re-run, an exact key match that already reached `complete` (and
passed verification) is **skipped**; any changed field mints a new job. This is
the cache-correctness rule from NEXT.md §"Large projects change the query
design" and §"profiles".

### 3.5 SQLite schema (transactional, resumable)

`corpus.db` under the artifact root:

```sql
CREATE TABLE runs (
  run_id     TEXT PRIMARY KEY,      -- caller-visible handle
  manifest   TEXT NOT NULL,         -- absolute path
  created_at INTEGER NOT NULL,
  cpu_budget INTEGER, mem_budget_mb INTEGER,
  state      TEXT NOT NULL          -- planning|running|paused|done|failed
);

CREATE TABLE jobs (
  job_id      INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL REFERENCES runs(run_id),
  input_path  TEXT NOT NULL,
  binary_sha  TEXT NOT NULL,
  cache_key   TEXT NOT NULL,        -- §3.4; UNIQUE(cache_key) enables skip
  project     TEXT NOT NULL,        -- derived <slug>-<sha12>
  profile     TEXT NOT NULL,
  heap_mb     INTEGER, max_cpu INTEGER,
  state       TEXT NOT NULL,        -- see §3.6 state machine
  priority    INTEGER DEFAULT 0,
  pid         INTEGER,              -- owning JVM while running
  enqueued_at INTEGER, started_at INTEGER, finished_at INTEGER,
  attempts    INTEGER DEFAULT 0,
  error       TEXT,
  UNIQUE(run_id, cache_key)
);

CREATE TABLE artifacts (           -- §4.2 manifests, linked to jobs
  job_id INTEGER REFERENCES jobs(job_id),
  path TEXT, schema TEXT, rows INTEGER, bytes INTEGER, sha256 TEXT
);
```

All state transitions are single-row `UPDATE`s inside a transaction, so a killed
scheduler leaves a consistent DB. (Recall the WSL-kill incident in NEXT.md: state
was reconciled through the DB, not re-derived.) Note: scheduler uses real
wall-clock; the *workflow/agent tooling* forbids `Date.now()`, but the CLI does
not — timestamps come from `std::time::SystemTime`.

### 3.6 Job state machine

```
discovered → queued → importing → analyzing → saving → verifying → complete
                 │          │          │          │          │
                 │          └──────────┴──────────┴──────────┴──→ failed
                 │                                             └──→ quarantined
                 └──→ skipped (cache_key already complete)
   any active state ──cancel──→ cancelled ;  ──kill──→ interrupted (needs verify)
```

- **saving → verifying**: import commits (one-shot import already does this;
  `handleAnalyze` calls `currentProgram.save`), then a **fresh JVM** reopens and
  checks identity + `invariants`.
- **verifying → quarantined** on a zero-header / unreopenable DB — never
  overwrite; quarantine and surface. (The Parasolid all-zero-header failure.)
- **interrupted**: a hard kill invalidates the persistence claim; on `resume`
  such jobs re-verify or re-run under their profile.
- `verifying` depends on Slice 2's `project verify`. **Sequencing note:** land a
  minimal `project verify` (reopen + count invariants) before Slice 3's verify
  stage, or ship Slice 3 with verification behind a `--verify` flag defaulting on
  once available.

### 3.7 CPU / memory token scheduler

```
parallel_jobs = min( cpu_budget / cores_per_job,
                     mem_budget  / (heap + jvm_overhead) )
```

- Memory usually binds first (RE jobs need 8/12/16 GB heaps) — reserve heap +
  native/JVM overhead per job.
- Resource-aware FIFO + priority; work-conserving (start a smaller job if it fits
  remaining tokens); optional longest-estimated-first to shrink the tail.
- Never two writers for one project identity.
- Stop completed analysis JVMs by default to release memory; lazy query-bridge
  startup only when someone queries.
- Timeout = execution time (`started_at`→now), excluding queue wait.
- Back off on host load / memory pressure instead of blindly launching `nproc`
  JVMs. Expose `-max-cpu` per job (measured resource, not proof of scaling).

### 3.8 Analysis profiles

- `inventory`: import metadata only, `-noanalysis` where possible (cheap exports,
  hashes, symbols, RTTI, strings — "label first, decompile last").
- `standard`: normal auto-analysis + baseline indexes.
- `deep`: expensive analyzers + decompile/p-code/export modules.
- custom: named profile whose options + hook hashes contribute to its identity.

### 3.9 Slice 3 acceptance criteria (from NEXT.md)

- [ ] Queue ≥20 mixed binaries; keep CPU budget busy without exceeding mem budget.
- [ ] One hash-isolated project per binary by default.
- [ ] Never two program executors for the same project identity.
- [ ] Survive scheduler restart; `resume` continues without redoing verified work.
- [ ] Live queued/running/saving/verifying state via `corpus status`.
- [ ] Cancellation never marks a cancelled write durable.
- [ ] A deliberately corrupted/unreopenable project is quarantined, not reused.
- [ ] An already-verified exact binary+profile is skipped on resume.
- [ ] Success declared only after a fresh JVM verifies identity + invariants.

Tests: a `corpus` integration test with a small fixture manifest (2–3 tiny
binaries), `require_ghidra!()`-gated; a DB-only unit test for state transitions,
dedup keys, and resume logic that runs without Ghidra.

### 3.10 Open questions (carried from NEXT.md)

- Scheduler packaging: in-CLI vs small local service vs daemon (state/protocol
  must not depend on the choice).
- Exact ownership/recovery semantics for clients that vanish mid-job.
- Whether cancelled analysis saves partial completed-analyzer results or always
  quarantines/retries per profile.
- Which verification invariants are universal vs profile-specific.

---

## Build order & dependencies

1. **Slice 4.1** (args + absolute path + envelope) — **DONE (2026-07-16).**
   Unblocks RE repos immediately.
2. **Slice 4.2** (artifact contract) — needed by 4.3 write modules and by 3's
   post-analysis exports.
3. **Slice 2 minimal `project verify`** — small, but a hard dependency of Slice
   3's `verifying` stage. Land the reopen+invariant check here.
4. **Slice 4.3/4.4** (module runtime + policy) — can proceed in parallel with 3.
5. **Slice 3** (corpus scheduler) — consumes 4.2 artifacts and 2's verify.

Each phase ships behind its own tests; nothing here requires a big-bang merge.
```

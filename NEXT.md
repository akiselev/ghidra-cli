# ghidra-cli next architecture

Status: design and implementation record, 2026-07-16. This document records lessons from the
`*-re` repositories, `RE-GUIDE.md`, the current `ghidra-cli` implementation,
and the Codex/Claude sessions that exercised Ghidra on large projects. Future
slices remain a plan; completed work is called out explicitly below.

The intended direction is:

1. keep one coordinated Ghidra execution lane per open project;
2. separate communications, queue management, status, and cancellation from
   that execution lane;
3. obtain machine-wide parallelism by scheduling independent hash-isolated
   projects;
4. make persistence verification and provenance part of success;
5. support checked-in Java scripts and multi-source modules as first-class jobs;
6. stream large RE artifacts rather than materializing giant response arrays.

## Implemented now: responsive bridge control plane

The first "busy looks dead" slice is implemented in the
`fix/bridge-busy-wait-in-queue` worktree:

- `GhidraCliBridge.run()` retains the original Ghidra script thread as the sole
  program execution lane.
- A dedicated acceptor and bounded client pool handle connections without
  dereferencing live Ghidra objects.
- Program commands receive IDs and enter a bounded FIFO job queue. Existing
  synchronous clients still wait for results, but connection-handler threads
  do not: completed job futures dispatch socket writes through a separate
  bounded response pool.
- `ping`, `status`, `bridge_info`, `job_status`, `job_cancel`, and `shutdown`
  bypass the program queue and use thread-safe lifecycle/job state plus cached
  project/program metadata.
- Every program job gets its own cancellable `TaskMonitorAdapter`, including
  observable message/progress snapshots. Queued jobs can be removed
  immediately; active cancellation is explicitly cooperative and reports
  `cancel_requested` until Ghidra reaches a cancellation check.
- `ghidra status` shows active work, while `ghidra jobs [JOB_ID]` and
  `ghidra cancel [JOB_ID]` expose queue inspection and cancellation to humans
  and JSON callers.
- Shutdown is drain-by-default. The Rust lifecycle now waits 300 seconds before
  force termination, configurable with `GHIDRA_CLI_SHUTDOWN_TIMEOUT`; `0` waits
  indefinitely. This replaces the unsafe three-second drain window.

Live integration coverage starts a real Ghidra 12.1.2 bridge, begins analysis,
observes the active job, proves a control-plane ping completes in under two
seconds, queues and observes eight additional program jobs, pings again after
that former connection-pool starvation threshold, cancels all eight queued
jobs, and allows analysis to finish. The strengthened run on 2026-07-16 passed
in 174.77 seconds and reported analyzer progress while control traffic
continued to succeed.

Repository validation covered every test binary. One monolithic run was
externally interrupted when WSL was killed during `project_tests`; stale state
was reconciled through the CLI, `project_tests` was rerun from the beginning,
and every not-yet-started test binary was then run explicitly. Final coverage
was 169 passed and 5 pre-existing snapshot tests ignored, with no failures.
`cargo check --all-targets`, `git diff --check`, and `ghidra doctor` also pass;
the doctor compiled the embedded Java bridge against installed Ghidra 12.1.2
and JDK 21. The only diagnostic is the pre-existing unused-import warning in
`src/ghidra/setup.rs` tests.

Live process samples during analysis showed the Ghidra JVM using roughly
114--186% CPU, direct evidence that "Ghidra is single-core" is not a valid
process-wide rule. `project_tests` also exercised independent project JVMs at
the same time. The conservative serialization rule applies to bridge-owned
handlers sharing one mutable program, not to Ghidra's internal workers or to
separate projects.

This implementation deliberately does **not** run two Ghidra program handlers
against one project concurrently. Durable cross-project bulk scheduling,
reconnectable result storage, protocol capability negotiation, executor
heartbeats beyond per-job progress/timestamps, and the module runtime remain
later slices below.

## Executive conclusion

`ghidra-cli` should become two cooperating systems:

- a durable, resource-aware corpus control plane in Rust; and
- a per-project Ghidra execution plane inside the Ghidra JVM.

The one-bridge-per-project rule is a good starting primitive. The former
one-thread-does-everything implementation was not; the implemented split keeps
only the Ghidra program lane serialized.

The bridge may and should accept connections, report status, expose queue
position, stream progress, and receive cancellation on threads that do not run
Ghidra program operations. A single program executor can remain the exclusive
owner of `currentProgram`, `GhidraState`, program switching, transactions, and
program-backed scripts. Thus a long analysis no longer makes the bridge appear
dead, while the risky part of Ghidra access remains coordinated.

Concurrency should first be scaled across independent projects. Parallel
read-only work inside one frozen project may be added later as an explicitly
constrained optimization; it must not be inferred from the fact that an
operation looks read-only.

## Evidence and lessons from the RE repositories

### Identity and isolation are fundamental

`RE-GUIDE.md` establishes the durable invariant: one binary hash and one
project database per run, raw evidence is immutable, and no two writers touch
one project concurrently.

The same policy has independently appeared in `parasolid-re`, `simbeor-re`,
`xpedition-re`, `cgm-re`, and the other RE repositories:

- binary identity is pinned by SHA-256;
- project names include a short content hash;
- generated evidence records project, program, hash, tool version, and command;
- completed imports are stopped and reopened in a fresh process;
- project results are not trusted until reopened metadata and expected counts
  are nonempty;
- large jobs use explicit heap settings, commonly 8--16 GB.

This repeated shell infrastructure belongs in `ghidra-cli` itself.

### In-memory success is not durable success

The first complete Parasolid analysis reported 45,246 functions in memory but
the old shutdown path interrupted persistence. A fresh process failed with
`java.io.IOException: Unrecognized file format`; the underlying database began
with an all-zero header and had to be quarantined.

The recovery contract became:

```text
import/analysis reports success
    -> persist and close cleanly
    -> reopen in a fresh Ghidra process
    -> verify binary/program identity and invariants
    -> only then export indexes or declare the job complete
```

The current one-shot import path is the right structural fix for initial
import: it commits the import before the persistent process-mode bridge opens
the program. Analysis also calls `currentProgram.save`. These improvements do
not remove the need for a first-class verification state, particularly for
scripts and bulk writes. `stop_bridge` also still has a three-second graceful
wait before it begins forceful termination, so shutdown must not be the only
durability mechanism.

### Tool output must be verified and fail closed

Real failures included:

- `--limit 0` silently exporting zero rows when callers meant unlimited;
- a malformed filter falling through to an unfiltered 184 MB result with exit
  status zero;
- case behavior making documented regular expressions return no matches;
- lifecycle commands producing plain text even when JSON was requested;
- scripts returning `executed` while producing no expected records;
- huge pretty-JSON arrays putting avoidable pressure on Rust and JVM heaps.

The transferable lesson is not merely to fix individual flags. Every command
needs a stable envelope, explicit counts, partial/failure records, atomic
artifact publication, and invariants that callers can verify.

### Large projects change the query design

Observed project sizes include:

- Parasolid: 45,246 functions, about 1.9 million symbols, and 839,201 direct
  call-graph edges;
- ACIS: 102,498 functions;
- FeatureWorks: 87,165 functions;
- D-Cubed: 23,995 and 26,601 functions for the main 2D/3D projects, with four
  major DLLs analyzed overall;
- CGM: 23,889 functions in the main project.

On ACIS, name-filtered function/symbol/decompile/memory requests took roughly
15--20 seconds apiece. Loops of queries hit outer shell timeouts even though
individual operations were reliable.

The current query layer deliberately fetches the complete dataset whenever it
needs the full Rust filter DSL, sorting, count, or offset. That is a useful
correctness fallback, but it is the wrong long-term data path for million-row
indexes. Filtering, projection, count, ordering, pagination, and streaming need
server-side implementations.

### Agents naturally create queue pressure

Multiple agents routinely query the same project. FeatureWorks exposed
transient `bridge not responding to ping` failures when the bridge was simply
busy. The current `fix/bridge-busy-wait-in-queue` branch removes the preflight
ping and lets connections wait in the socket backlog. Five concurrent
decompiles were successfully exercised with that behavior.

This establishes the required user-visible semantic: a busy bridge queues by
default. It does not establish that the operating-system accept backlog is a
sufficient job system. It has no durable job identity, queue position,
fairness, progress, ownership, cancellation, reconnection, or result recovery.

### RE is tiered, not uniformly deep

`RE-GUIDE.md` says "label first, decompile last." Cheap, high-confidence assets
such as hashes, file metadata, exports, symbols, RTTI, strings, sibling builds,
vendor documentation, and direct call structure should be exhausted before
mass decompilation.

Bulk orchestration therefore needs profiles such as:

- `inventory`: import or inspect metadata with no auto-analysis where possible;
- `standard`: normal auto-analysis and baseline indexes;
- `deep`: expensive analyzers, decompilation/export modules, p-code, and other
  campaign-specific hooks;
- a named custom profile whose options and hooks contribute to its identity.

The cache key is not only the binary hash. It includes the Ghidra version,
loader/language/compiler selection, analyzer options, script/module hashes, and
other settings that materially affect the resulting database.

## What "single-threaded" actually means

### The old statement is too broad

`PLAN-java-plugin.md` says that Ghidra headless is single-threaded for program
access and therefore makes the socket accept loop sequential. This conflates
three different questions:

1. Can Ghidra itself use multiple threads? Yes. `AutoAnalysisManager` has an
   analysis thread and a shared analysis worker pool, and `analyzeHeadless`
   exposes `-max-cpu`.
2. Can networking and control-plane work happen concurrently with a Ghidra
   operation? Yes. No Ghidra constraint requires `ServerSocket.accept`, JSON
   parsing, queue bookkeeping, status, logs, and cancellation to run on the
   program executor.
3. Can arbitrary handlers concurrently access one mutable `Program`? There is
   no safe blanket promise on which this CLI should rely. Ghidra has locks,
   transactions, task monitors, internal analysis scheduling, and background
   work, but APIs and iterators do not all share a uniform concurrency contract.

The useful invariant is therefore "one coordinated program-access lane," not
"one thread in the entire bridge process."

### Why program operations remain coordinated

The current bridge shares mutable process-wide/script-wide objects:

- the inherited `currentProgram` field;
- the inherited `state` and `monitor` fields;
- the current project and program consumer;
- open/switch/release logic;
- program managers, iterators, and domain objects;
- write transactions and saves;
- arbitrary agent-authored scripts.

Analysis is especially important: it mutates the program extensively while
internally scheduling analyzers and workers. A query that is semantically a
read may still observe changing tables or hold an iterator while analysis or a
write changes the underlying model. Program switching can release the exact
object another handler is using. Two writes may also create independently
valid-looking transactions whose higher-level effects are not composable.

Serializing these operations is a reliability policy around a mutable Ghidra
session, not evidence that every Ghidra database read is physically incapable
of concurrency.

### The former bridge coupled unrelated work

Before the responsive-control implementation above, `GhidraCliBridge.run()`
performed this entire sequence on one thread:

```text
accept socket
    -> read request
    -> parse JSON
    -> dispatch and execute full Ghidra operation
    -> serialize result
    -> write response
    -> accept next socket
```

Consequences:

- a long analysis prevents `ping`, `bridge_info`, status, shutdown, and cancel
  from being handled;
- the bridge looks dead while it is working correctly;
- clients cannot distinguish queued, running, saving, or wedged;
- the socket backlog is the only queue and cannot be inspected;
- a disconnected client has no durable handle with which to recover a result;
- a large response blocks admission of later control messages;
- shutdown tends toward out-of-band PID killing because the in-band shutdown
  request is itself stuck behind the long operation.

These are bridge architecture problems, not forced consequences of Ghidra.

## Per-project bridge redesign

### Thread and ownership model

Use at least these logical components:

```text
client sockets
    -> acceptor / connection handlers
       -> control router -----------------> immediate control responses
       -> bounded program-job queue
            -> single program executor ---> Ghidra Program / state / scripts
                    |
                    +-> job registry snapshots, progress, result/artifacts
                              |
                              +-> status/event subscribers
```

The roles are:

#### Acceptor and connection handlers

- Always remain responsive while program work is running.
- Parse and validate request envelopes.
- Assign a job ID before enqueueing program work.
- Enforce request/body/output limits.
- Put immutable request DTOs on a bounded queue.
- Wait on a completion future for synchronous compatibility, or return the job
  ID immediately for asynchronous commands.
- Never retain or access `Program`, `Function`, `Symbol`, `Listing`, iterator,
  decompiler result, or other Ghidra model objects.

An executor service or lightweight thread-per-connection model is adequate at
the current scale. It must be bounded so idle or malicious clients cannot
exhaust the JVM.

#### Control router

The following commands do not need to wait for the program executor if their
responses come from thread-safe job/bridge state rather than live Ghidra
objects:

- `ping`;
- protocol/capability negotiation;
- bridge uptime and lifecycle state;
- queue listing and queue position;
- job status and progress snapshot;
- job log/event subscription;
- cancellation request;
- drain/shutdown request;
- health data such as executor heartbeat and last completed job.

`bridge_info` currently reads live project/program objects. Split it into a
pure control-plane snapshot and a separately queued live `program_info` query.
The executor publishes immutable snapshots whenever the project/program state
changes.

#### Program executor

- Is the only bridge-owned thread that dereferences mutable Ghidra program and
  script state.
- Resolves string addresses/names to Ghidra objects after dequeueing, never in
  the socket thread.
- Owns open/switch/release, transactions, saves, analysis, and module execution.
- Publishes progress and state through immutable/atomic job-registry updates.
- Produces plain result DTOs or declared artifact paths before completing the
  job; Ghidra objects never cross back to connection threads.
- Has an executor heartbeat so status can distinguish a long-running task from
  a dead executor.

This preserves the current correctness model while solving bridge
responsiveness.

### Job protocol

Every program operation should have a job record even if the CLI presents it
synchronously:

```text
job_id
request_id / idempotency key
project and program identity
command and normalized arguments
read/write/analysis/module class
owner/client metadata
enqueue/start/finish timestamps
state and queue position
progress maximum/current/message
active executor heartbeat
source/module/profile hashes
result envelope or artifact manifest
error and partial-result metadata
cancellation state
verification state
```

Suggested states:

```text
queued -> running -> saving -> verifying -> complete
                    |          |
                    |          +-> verification_failed -> quarantined
                    +-> failed / cancelled / interrupted
```

Do not retry a request after bytes have been sent unless the protocol has an
idempotency key and the server can return the original job. The current client
correctly retries only pre-send connection failures; preserve that property.

### Cancellation and shutdown

Ghidra's `TaskMonitor` contract includes `cancel()`, `isCancelled()`, and
`checkCanceled()`. `TaskMonitorAdapter` stores cancellation in a volatile flag.
This gives the control thread a legitimate cancellation channel without
touching `Program`.

The active job should publish its own cancellable monitor. The control router
sets cancellation on that monitor. Program code and Ghidra APIs receive that
monitor and cooperate by checking it.

Care is needed for `analyzeAll`: `FlatProgramAPI.analyzeAll` ultimately passes
the inherited `GhidraScript.monitor` into `AutoAnalysisManager.startAnalysis`.
The bridge must either install a per-job monitor around executor work and
restore the bridge monitor afterward, or invoke the analysis manager through a
well-tested wrapper that accepts the job monitor. It must not casually cancel
the headless bridge's lifetime monitor and accidentally terminate the server.

Cancellation is cooperative. Some Ghidra operations or third-party scripts may
not check their monitor promptly. Status must distinguish `cancel_requested`
from `cancelled`. A later hard process kill is a last resort and invalidates
the job's persistence claim.

Shutdown modes should be explicit:

- `drain`: reject new jobs, finish the active job, save/close, exit;
- `cancel-and-drain`: cancel active work, wait for a safe boundary, then close;
- `force`: external last resort; mark active/write jobs interrupted and require
  verification or quarantine on restart.

### Progress and liveness

Progress should be independent of the original client connection. Clients can
disconnect and later use `job status` or `logs --follow`.

The executor should report:

- current phase, not only a percentage;
- Ghidra monitor message/progress where available;
- last heartbeat time;
- elapsed time;
- whether cancellation is enabled/requested;
- save and verification phases separately;
- queue depth and position.

For one-shot headless analysis workers, the outer Rust scheduler owns the
process and can supplement Ghidra progress with PID, CPU time, resident memory,
log-tail timestamps, and phase markers. A blocked in-process bridge should not
be the sole source of truth for whether analysis is alive.

### Possible future read parallelism

Parallel reads within one project are not required for the first redesign.
They may be possible under a narrower contract after measurement and stress
testing:

- the program is fully analyzed, saved, and verified;
- no writer, analyzer, program switch, or module with undeclared effects is
  active or queued ahead of the reads;
- each worker uses independent stateful helpers such as its own
  `DecompInterface`;
- a writer-preferring read/write lease prevents writer starvation;
- the program modification number/generation is checked before and after the
  read;
- returned values are detached DTOs, never live model objects or iterators;
- known-unsafe handlers stay on the exclusive lane;
- concurrency is disabled for Ghidra versions or APIs without a validated
  contract.

A safer alternative for very high same-binary read throughput is to export a
stable index once and query it outside Ghidra, or run read-only work against
separate packed/snapshot copies. Most useful throughput still comes from
parallel independent projects, which avoids this complexity entirely.

## Bulk corpus scheduler

### Command shape

Introduce a distinct corpus/job interface rather than overloading the existing
`batch` command:

```text
ghidra corpus plan MANIFEST
ghidra corpus analyze MANIFEST [--jobs auto]
ghidra corpus status [RUN_ID]
ghidra corpus logs RUN_ID [--follow]
ghidra corpus cancel RUN_ID|JOB_ID
ghidra corpus retry RUN_ID|JOB_ID
ghidra corpus resume RUN_ID
```

The existing `batch` command is a sequential command macro against one bridge.
It also uses whitespace splitting rather than shell-quality quoting. Preserve
or repair it for interactive use, but do not mistake it for a corpus scheduler.

### Manifest

Each input record should support:

```text
input path and expected SHA-256
project root and derived project name
program name
loader / processor / compiler spec
analysis profile and analyzer properties
heap reservation
max CPU cores
per-file timeout policy
pre/post scripts or modules
expected verification invariants
priority/tags/campaign identity
artifact output root
```

The default project name should be a sanitized basename plus a content hash,
for example `<slug>-<sha12>`. Distinct hashes never silently reuse a project.

### Durable state machine

Store scheduler state in SQLite or another transactional local database:

```text
discover/hash
    -> queued
    -> one-shot import
    -> analyze
    -> persist/close
    -> fresh-process reopen verification
    -> post-analysis modules/exports
    -> complete
```

Failed persistence moves a project to quarantine rather than overwriting it.
An interrupted scheduler can resume without redoing verified work. Exact
binary/profile matches can be skipped; changed inputs or profiles create new
jobs.

### CPU and memory scheduling

Ghidra analysis often appears dominated by one CPU core, but it is not correct
to encode "Ghidra is single-core" as an absolute. Headless Ghidra exposes
`-max-cpu`, and some analyzers use its internal worker pool.

Expose and benchmark per-job cores. The scheduler should allocate both CPU and
memory tokens:

```text
parallel jobs = min(
    cpu_budget / cores_reserved_per_job,
    memory_budget / memory_reserved_per_job
)
```

Memory reservation must include heap plus JVM/native overhead. Existing RE jobs
have needed 8, 12, or 16 GB heaps, so memory may constrain concurrency before
logical CPUs do.

Useful scheduling properties:

- resource-aware FIFO with priority overrides;
- work-conserving dispatch when a smaller job fits available tokens;
- optional longest-estimated jobs early to reduce the final tail;
- no simultaneous writers for the same project identity;
- completed analysis JVMs stopped by default to release memory;
- lazy query bridge startup after completion;
- timeout measured as job execution time, not time spent waiting in a queue;
- host load and memory pressure backoff rather than blindly launching `nproc`
  JVMs.

### Bulk acceptance criteria

An initial milestone should:

- queue at least 20 mixed binaries;
- keep the configured CPU budget busy without exceeding the memory budget;
- create one hash-isolated project per binary by default;
- never run two program executors for the same project;
- survive scheduler restart and resume jobs;
- expose live queued/running/saving/verifying state;
- allow cancellation without calling a cancelled write durable;
- quarantine a deliberately corrupted/unreopenable project;
- skip an already verified exact binary/profile on resume;
- declare success only after a fresh JVM verifies project identity and
  invariants.

## Java scripts and module runtime

### Present gap

The Rust client already sends `path` and `args` for `script_run`, but the Java
bridge:

- ignores the `args` array;
- checks `new File(scriptPath).exists()` relative to the bridge's inherited
  working directory;
- calls `runScript(scriptPath)` without arguments;
- relies separately on Ghidra's script-name/source-directory lookup;
- returns only `status: executed`;
- does not capture a structured result or prove expected output exists;
- advertises inline Java/Python surfaces that the bridge reports unsupported.

RE repositories work around this by copying scripts into a global
`~/.config/ghidra-cli/scripts` directory, stopping the bridge, starting it from
that directory, and passing output paths through inherited environment
variables. This is fragile, global, stateful, and hostile to concurrent agents.

### Ghidra capabilities already available

Ghidra 12.1.2 provides:

- `GhidraScript.runScript(String, String[])` and `setScriptArgs`;
- `analyzeHeadless -scriptPath` plus pre/post-script arguments;
- source bundles containing multiple Java sources;
- intra-bundle and inter-bundle package use;
- `//@importpackage` dependencies;
- OSGi `META-INF/MANIFEST.MF` import/export metadata;
- external JAR bundles and versioned package requirements;
- `BundleHost` operations to add, enable, disable, remove, resolve, install,
  activate, and deactivate bundles.

The old plan's assumption that multi-file Java necessarily requires a full
extension build is too restrictive for current Ghidra. Version capability
checks and a single-script fallback are still necessary because `ghidra-cli`
claims support for older Ghidra versions.

### Proposed user surface

```text
ghidra script run path/ExtractThing.java -- arg1 arg2

ghidra module validate path/to/module
ghidra module run path/to/module --entry ExtractThing.java -- arg1 arg2
ghidra module list
ghidra module doctor path/to/module
```

A module is a checked-in source-bundle root containing some combination of:

```text
module metadata
one or more Java sources
META-INF/MANIFEST.MF
declared JAR/OSGi dependencies
entry script
read-only or write effect declaration
expected structured outputs/artifacts
supported Ghidra version range
```

### Loading and caching

- Resolve an absolute module root; do not depend on bridge CWD.
- Hash all sources, manifest data, and dependencies.
- Register a content-addressed bundle root with Ghidra's bundle host.
- Cache compilation by module hash, dependency hashes, Ghidra version, and JDK
  version.
- Reload when the content hash changes; do not let classloader state silently
  serve stale code.
- Keep concurrently active module identities isolated where OSGi permits.
- Return compilation diagnostics as structured job errors.
- Record the exact module hash in all results and project-write provenance.

### Execution policy

Use a hybrid model:

- small read-only extractors may run on the persistent bridge's program
  executor;
- write modules require exclusive program execution, transactions where
  possible, backup, save, and verification;
- dependency-heavy, classpath-changing, or especially important write modules
  may run as one-shot headless post-script jobs for stronger lifecycle and
  classloader isolation;
- no module runs concurrently with analysis on the same mutable program;
- arbitrary Java is trusted code with the user's filesystem/JVM privileges,
  not a sandbox.

### Results

Scripts should not communicate primarily through inherited environment
variables or untracked stdout.

Provide a small result/artifact contract:

- stdout/stderr captured separately from protocol output;
- small structured return value in the job result;
- large results written to declared temporary paths and atomically renamed;
- JSONL preferred for per-function or other large collections;
- artifact manifest includes schema, row count, byte size, checksum, project,
  program, binary hash, Ghidra version, module hash, arguments, and failures;
- an expected artifact that is absent or empty fails the job unless explicitly
  allowed;
- partial per-function errors are records, not silently dropped rows.

### Module acceptance criteria

- A checked-in Java script receives real positional arguments without an
  environment-variable workaround.
- An absolute script path works without copying to the global script directory
  and without changing bridge CWD.
- A multi-source bundle imports a sibling package and runs without a full
  Ghidra extension build.
- A module with an external JAR dependency is version-resolved and
  content-addressed.
- Editing a source invalidates the compile cache and cannot execute stale code.
- A read-only extractor returns a validated JSONL artifact.
- A write module runs exclusively, persists its transaction, and passes a
  fresh-process verification gate.
- Status and cancellation remain responsive while a long module runs.

## RE-native data operations

### Server-side query execution

Move the full supported filter grammar, field projection, count, sort, offset,
and limit into the Java/data side, or define a bridge query AST that can be
evaluated while iterating. Preserve a client fallback only for compatibility.

Results should support pages or streaming frames so a 1.9-million-symbol table
does not exist as one Java `JsonArray`, one socket line, one Rust `Vec<Value>`,
and one pretty-printed `String` in succession.

### Structured function export

Add a built-in bulk export or bundled module that emits one JSONL record per
function with fields such as:

```text
binary path/hash and Ghidra identity
program and function name
entry address and body/address range
signature and calling convention
thunk/external/library flags
decompiled C/pseudocode
token spans
direct calls and callers
p-code and basic-block information when requested
analysis/decompilation warnings
per-function failure and elapsed time
```

Reuse one `DecompInterface` per program/executor instead of constructing one
for every function. A future parallel export pool must use one independent
interface per worker. Decompiled C is analysis text, not recovered source, so
addresses, tokens, p-code, Ghidra version, and failure provenance are
first-class.

The direct call graph is insufficient for virtual dispatch, function pointers,
and other indirect flows. Provide optional p-code/reference-oriented exports
instead of implying that direct `getCalledFunctions` edges are complete.

### Transactional annotation/apply

Bulk rename, comment, type, signature, and patch operations need:

- plan/dry-run output;
- binary/project/module/catalog provenance;
- idempotency keys;
- one exclusive write job;
- bounded/staged transactions where possible;
- rollback or an explicit backup restoration route;
- save followed by fresh-process verification;
- counts and spot/invariant checks in the result.

This turns the `RE-GUIDE.md` apply-and-verify discipline into a reusable CLI
contract rather than a collection of repository scripts.

## Protocol and compatibility

Add a versioned handshake that reports:

```text
bridge protocol version
Ghidra and Java versions
supported command/capability set
job/status/cancel support
module/bundle support
streaming formats and maximum frame size
server-side query features
analysis CPU controls
current project/program identity snapshot
```

The README and CLI help must be generated from or tested against capabilities.
They currently imply inline Java/Python support that the Java bridge rejects.
Older bridges should produce a clear capability error instead of triggering an
ambiguous restart or falling through to mismatched behavior.

## Implementation sequence

### Slice 0: preserve the immediate busy-bridge fix

- Carry the semantic of commit `6940855` through any daemonkit/bridge rework:
  clients wait by default and only retry pre-send connection failures.
- Add stress coverage for several simultaneous short and long requests.
- Do not treat this socket-backlog behavior as the final queue implementation.

### Slice 1: split communications from execution (busy/dead portion implemented)

- Introduce bounded connection handling and immutable request DTOs.
- Add an explicit in-memory per-project job queue and registry.
- Move all Ghidra object access to one program executor.
- Handle ping/capabilities/job status/cancel/drain from the control plane.
- Add per-job monitors, progress snapshots, executor heartbeat, and synchronous
  compatibility over job futures.
- Add graceful drain and explicit interrupted-state recovery.

This slice directly fixes the "busy looks dead" family of problems without
requiring risky concurrent `Program` access.

The implemented portion covers bounded connection handling, explicit queue and
registry, single program ownership, responsive status/cancel/drain, per-job
monitors, synchronous compatibility, and graceful drain. Capabilities,
executor heartbeat beyond job timestamps/progress, and richer interrupted-job
recovery remain open work.

### Slice 2: lifecycle and data correctness

- Implement `project verify` and integrate fresh-process verification into
  write/analysis job completion.
- Unify output envelopes and lifecycle JSON behavior.
- Add atomic artifact manifests and result counts.
- Add protocol/capability negotiation.
- Move common filtering/count/pagination server-side and add streaming.

### Slice 3: durable corpus scheduler

- Define manifest/profile schemas.
- Add a transactional scheduler database and job state machine.
- Add hash-isolated project derivation, deduplication, resume, retry, and
  quarantine.
- Add CPU/memory token scheduling and expose `-max-cpu`.
- Add status/log/cancel commands and lazy post-analysis bridge startup.

### Slice 4: script and module runtime

- First fix argument passing and absolute source-root resolution.
- Add captured output and structured artifact validation.
- Add content-addressed multi-source bundles and dependency support with
  Ghidra-version capability gates.
- Add read/write declarations, trust policy, transactions, and one-shot mode.

### Slice 5: RE-native bulk export and apply

- Streaming per-function decompile/token/p-code/call export.
- Indirect-call/reference enrichment.
- Transactional annotation plans and verified apply.
- Integration hooks for downstream systems such as decombine2.

## Decisions

- Keep project-level program execution serialized initially.
- Split networking/control/status/cancel from program execution.
- Scale analysis across hash-isolated projects.
- Treat `-max-cpu` as a measured resource parameter, not proof that every
  analyzer scales or that Ghidra is absolutely single-core.
- Make every operation a job internally, even when exposed synchronously.
- Make fresh-process verification part of successful analysis/write jobs.
- Prefer structured streaming artifacts over giant response arrays.
- Support checked-in Java source bundles before pursuing ad hoc inline Java.
- Treat arbitrary Java modules as trusted, provenance-recorded code.
- Do not add concurrent same-program reads until a narrow contract is tested.

## Open design questions

- Whether the durable corpus scheduler belongs in the CLI process, a daemonkit
  service, or a small separate local service. The state/protocol should not
  depend on that packaging decision.
- Exact SQLite schema and ownership/recovery semantics for clients that vanish.
- Whether synchronous requests wait on the same socket or immediately return a
  job ID above a duration/size threshold.
- How much Ghidra monitor progress is meaningful enough to expose across
  analyzers.
- Whether cancelled analysis should save partial completed-analyzer results or
  always quarantine/retry under each profile.
- Which Ghidra versions have sufficiently stable `BundleHost` APIs for dynamic
  multi-source module loading.
- Whether safe same-project read parallelism is worth its complexity after
  server-side indexes and cross-project parallelism are available.
- How module dependency trust and allowlisting should work for autonomous
  agents.
- Which verification invariants are universal versus profile-specific.

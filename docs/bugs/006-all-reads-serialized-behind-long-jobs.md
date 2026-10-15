# 006: Every read-only command is serialized behind long jobs on a single program thread

- **Observed:** 2026-10-15, 12-agent shared-bridge trial (parasolid-re
  `artifacts/campaigns/20261015-haiku-trial/`)
- **CLI:** `ghidra 0.2.2` (commit `c9aefa1`), Ghidra 12.1.2, OpenJDK 21
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll` (45,246 functions, 72.7 MB image)

## Symptom

Each worker runs one GhidraScript that decompiles its 200–270 scope functions. That takes about
4–5 minutes. With 5 such `script_run` jobs queued, any cheap command (`program info`, `memory read`,
`function get`) waits about 25 minutes. Snapshots from `ghidra jobs --json`:

| time | queue_depth | active | queued |
|---|---|---|---|
| ~11:20 | 35 | `script_run` 163 s | 24 `program_info`, 1 `open_program` |
| ~11:25 | 36 | `script_run` 241 s | (mostly `program_info`) |
| ~12:10 | 8 | `script_run` 287 s | 5 `script_run`, 3 `program_info` |

Effects on the trial:
- one worker gave up on a 4-byte `memory read` of the version table and shipped with empty version columns;
- workers lost 30+ minutes each to the preflight check alone (see 001);
- several workers misread timeouts as a hung bridge.

## Cause

`GhidraCliBridge` runs every program job on the original GhidraScript thread (~L305, "Deliberately run
program jobs on the original GhidraScript thread"). Only control commands (`ping`, `status`,
`bridge_info`, `job_*`, `shutdown`) skip the queue. Reads and writes share one FIFO queue.

## Experiment: concurrent reads are safe and fast

I ran `ConcRead.java` (below) on a private copy of the project, on its own bridge, with 64 imprint functions. Per function
it does a `getFunctionAt`, `getReferencesTo`, a 64-byte `Memory.getBytes`, and a full decompile with a
per-thread `DecompInterface`. It runs the 64 serially, then on a fixed pool of 8 threads, and compares
the per-function results:

```
n=64 serial_ms=140383 parallel8_ms=38510 mismatch=0 errors=0
```

That is 3.6× faster with identical output and no exceptions. This matches how Ghidra itself works:
the GUI reads the program from Swing while auto-analysis runs, and `ProgramDB` managers guard their
state with the domain-object lock. Concurrent *writes* are a different matter. They need transactions
and must stay serialized.

## Suggested fix

1. **Read/write split.** Classify each command as read or write:
   - read: `program_info`, `get_function`, `list_*`, `decompile`, `xrefs_*`, `read_memory`, `disasm`,
     `find`, `graph`, `stats`, `dump`, ...
   - write: `rename_*`, `create_*`/`delete_*`, comments, tags, types, `patch`, `analyze`, `import`,
     `open_program`, `program_close`.

   Run read jobs on a bounded pool (default `min(8, cores/2)`, configurable) under the read side of a
   `ReentrantReadWriteLock`. Run write jobs on the program thread under the write lock. Use a fair lock,
   so a queued writer stops new readers until it gets the lock and isn't starved.
2. **Scripts.** Treat `script_run` as a writer by default. Add `ghidra script run --read-only`, which
   runs the script as a reader. Record `program.getModificationNumber()` before and after the run; if it
   changed, fail the job loudly ("read-only script modified the program") and log it. Most analysis
   scripts are read-only, and this lets them run alongside each other and next to cheap queries.
3. **Cheap lane, even before (1).** Answer `program_info` from the bridge snapshot as a control command
   (this is fix 1 of 001). Also give small reads (`get_function`, `read_memory`, `xrefs_*` with a
   limit) priority over `script_run`/`decompile` in the queue. Both are useful on their own, but
   neither fixes a single 5-minute job blocking everything.
4. **Per-thread decompiler.** Handlers already create a `DecompInterface` per call (~L842). Keep that,
   or pool one per worker thread. Never share one across threads.
5. **Visibility.** Add `lane`, `queue_position` and `blocked_by` (the active job ids) to `ghidra jobs`
   and to timeout messages.

Recommended order: 001 (snapshot preflight), then 005 (drop abandoned jobs), then 006.1 + 006.2 (read pool
and `--read-only` scripts). The first two are small and remove most of the queue in this trial.
006.1 + 006.2 removes the head-of-line blocking.

## Evidence

- Experiment script: `docs/bugs/006-ConcRead.java`. It was run on a private copy of the project (since deleted), on its own bridge.
- Queue snapshots: taken during the trial with `ghidra jobs --project parasolid-c900fa3f430f --json`.
- Worker bug notes: `artifacts/campaigns/20261015-haiku-trial/*/ghidra-cli-bugs.md` in parasolid-re.

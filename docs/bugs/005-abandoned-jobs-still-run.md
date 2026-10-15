# 005: Jobs whose client has gone away still run, adding to queue contention

- **Observed:** 2026-10-15, during a 12-agent shared-bridge trial (parasolid-re
  `artifacts/campaigns/20261015-haiku-trial/`)
- **CLI:** `ghidra 0.2.2` (commit `c9aefa1`) at `~/.cargo/bin/ghidra`
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll`, one shared bridge

## Symptom

A client gives up on a request in one of three ways: its read timeout fires (300 s by default), the
caller kills it, or the agent driving it is interrupted. The job it queued is not removed. It still runs
when it reaches the head of the queue, and its result is written to a closed socket.

Observed: after all 13 agents of the trial were stopped by a user interrupt, `ghidra jobs` still showed
`queue_depth` 7 (one `xrefs_to` running and six `program_info` queued) with no live clients behind them. The relaunched
workers then queued behind those jobs. Workers that hit the 300 s timeout typically re-issued the same
command, so each timeout added a duplicate job, sometimes plus the `open_program` fallback from 001.

## Cause (from source, `c9aefa1`)

`GhidraCliBridge.serveClient` (~L376) parses the request, enqueues the job, and registers a
`whenComplete` callback that writes the response. Nothing watches the connection between enqueue and
completion, and `executeProgramJob` never checks whether anyone is still waiting.

## Suggested fix

1. Keep the `Socket` in the `ProgramJob`. Before `executeProgramJob` starts a job, probe the connection:
   set a 1 ms soTimeout and `read()`. `-1` (EOF) or an `IOException` other than a timeout means the
   peer is gone, so mark the job `abandoned` and skip it.
2. For a running long job (decompile, script_run), poll the socket the same way every few seconds from
   the response executor. On EOF, set `cancel_requested` on its `JobTaskMonitor`. Decompiles and scripts
   already honour the monitor.
3. On client read timeout, the Rust client should send `job_cancel` for its job id before exiting. That
   needs the bridge to return the job id early, for example as a first `{"queued": id}` line.
4. List abandoned jobs in `ghidra jobs` with state `abandoned`, so the count shows up.

Related: 001 (preflight jobs), 006 (no read concurrency).

# 001: Per-invocation `program_info`/`open_program` preflight queues behind long jobs and times out

- **Observed:** 2026-10-15, ~02:08–02:26 PDT
- **CLI:** `ghidra 0.2.1` installed at `~/.cargo/bin/ghidra`, SHA-256
  `51be279bb3c3a35835863c299df11cb21f18efb2fa0c6b3e565ebbc20ae4e48f` (repo HEAD at the time: `10019ba`, 0.2.2)
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll` (66 MB `.text`, 44,999 functions), `GHIDRA_HEADLESS_MAXMEM=8G`
- **Load:** one shared bridge, six to nine agents issuing commands concurrently, about 16–20 decompiles queued at the peak

## Symptom

Small, cheap commands fail with a client read timeout while the bridge is busy, even though the
requested program is already open:

```text
Error: Bridge did not respond within 300s while running 'open_program' — the program job is still
queued or running. Inspect `ghidra jobs`, raise the wait via GHIDRA_CLI_READ_TIMEOUT (seconds; 0 = wait
indefinitely), or use GHIDRA_CLI_OP_TIMEOUT for long analyze/import operations.
```

Failures recorded (the size is the target function's body size, so this is not a "big function" problem):

| Command | Target | Function size | Result |
|---|---|---|---|
| `decompile` | `0x1801a87e0` | 12,298 B | rc=1, the error above (twice, on retry too) |
| `decompile` | `0x180ad7be0` | 4,231 B | rc=1, the error above (twice) |
| `disasm -n 3000` | `0x1823fae30` | — | rc=1, the error above; `ghidra jobs` showed queue depth 16 |
| `function list` (full export) | — | — | timed out after 300 s |
| `decompile` | `0x180922850` | 64,795 B | killed by the caller's `timeout 900` (rc=124), empty output |
| `decompile` | `0x18320ef10` | 95,276 B | killed by the caller's `timeout 900` (rc=124), empty output |

The same decompiles succeeded later, once the queue drained.

## Repro

1. Start a bridge on a large program.
2. From several shells, queue about 15 decompiles of large functions (each takes minutes).
3. From another shell, run `ghidra decompile <small function> --project P --program X`.

Expected: the small command waits only for its own decompile (or reports its queue position).
Actual: it fails after 300 s in `open_program`, a call it should not need to make.

## Cause (from source, HEAD `10019ba`)

- `src/main.rs` ~L660–671: every invocation that names a program first calls `client.program_info()`. If
  that call returns an error (a timeout counts), it falls back to `client.open_program(...)`. Otherwise
  it compares names and calls `open_program` only on a mismatch.
- `src/ghidra/scripts/GhidraCliBridge.java` ~L585–625: only `ping`, `status`, `bridge_info`,
  `job_status`, `job_cancel` and `shutdown` are control commands. `program_info` and `open_program` are
  ordinary program jobs, placed on `programQueue` and run serially on the single GhidraScript thread
  (~L304, "Deliberately run program jobs on the original GhidraScript thread").
- So each CLI call adds one or two preflight jobs behind every queued decompile. The preflight read uses
  the 300 s default (`src/ipc/client.rs` L23 `DEFAULT_READ_TIMEOUT_SECS`). A timed-out `program_info`
  then triggers an `open_program` that also queues. The user's real command is never sent.

## Suggested fix

1. Answer `program_info` from the bridge snapshot (`refreshBridgeSnapshot`, ~L1107) as a control
   command, without queuing on the program thread.
2. Do not fall back to `open_program` when `program_info` *timed out*; only on a definite "no program"
   or name-mismatch answer.
3. Optionally fold the program check into the real request: the bridge rejects with a typed mismatch error
   and the client opens and retries only then.
4. In the timeout message, report the job's queue position (and the IDs of the jobs ahead of it), so the
   user can tell contention from a hang.

## Evidence

`/home/dev/projects/parasolid-re/artifacts/reviews/20261015T-c900fa3f430f-docs-review/size-drivers/`
`api-lattice-mass/failures.txt`, `api-lattice-mass/dec/1801a87e0.err`,
`faceting-drawing/failures.txt` (item 2), `boolean-sewing/failures.txt`,
`local-ops/errors.txt` (`180922850`), `core/` (`functions-live.err`).

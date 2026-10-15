# 002: An unsupported command silently restarts a shared bridge, killing other clients' jobs

- **Observed:** 2026-10-15T08:13:39Z–08:14:25Z
- **CLI:** `ghidra 0.2.1`, SHA-256 `51be279bb3c3a35835863c299df11cb21f18efb2fa0c6b3e565ebbc20ae4e48f`
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll`, a bridge shared by several concurrent clients

## Symptom

One client ran `ghidra memory search 09 01 00 00 03 02 00 00 0a 03 00 00 --limit 20`. The CLI printed

```text
Bridge command not supported by running instance. Restarting bridge and retrying...
```

It stopped and restarted the bridge, then the retry still failed with `Unknown command: search_memory`.
`ghidra jobs` afterwards showed a bridge uptime of about 9.7 s. Jobs queued or running for other clients at
that moment were lost, and those clients saw failures they could not explain. Nobody asked for the restart.

## Cause (from source, HEAD `10019ba`)

`src/main.rs` ~L676–712: when the first attempt returns an "Unknown command" error (or a stale
`list_functions` response), the CLI calls `bridge::stop_bridge` and `ensure_bridge_running`
unconditionally. It does not check whether other jobs are queued or running, or whether the restarted
bridge will actually support the command. In this case it did not: `search_memory` was still unknown after
the restart, so the restart was pure damage.

## Suggested fix

1. Never stop a bridge that has queued or running jobs, or other connected clients, without an explicit
   flag. Fail with a clear "bridge version X lacks command Y; run `ghidra restart` when idle" error instead.
2. Before restarting, compare the CLI's embedded bridge script version with the running bridge's
   (`bridge_info`). Restart only if the embedded script actually provides the command.
3. If a restart does happen, drain first: stop accepting jobs and wait for running ones to finish, then
   restart.

## Evidence

`/home/dev/projects/parasolid-re/artifacts/reviews/20261015T-c900fa3f430f-docs-review/cpp-faceting/commands.log`
lines 55–58.

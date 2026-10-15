# Known bugs

Each file records one reproducible defect with the exact error text, the versions involved, a
source-level cause where known, and a suggested fix.

| ID | Summary | Severity | Status |
|---|---|---|---|
| [001](001-preflight-program-jobs-block-behind-long-decompiles.md) | Per-invocation `program_info`/`open_program` preflight queues behind long jobs; cheap commands time out after 300 s | high (shared bridges) | fixed (unreleased) |
| [002](002-unknown-command-auto-restarts-shared-bridge.md) | An unsupported command auto-restarts a shared bridge, killing other clients' jobs | high (shared bridges) | fixed (unreleased) |
| [003](003-decompile-response-buffer-exceeded.md) | `decompile` fails with "Response buffer size exceeded" on ~44–65 KB functions (fixed: 512 MB default, `--max-payload-mb`) | medium, fixed | fixed (0.2.2, c9aefa1) |
| [004](004-function-disasm-ignores-limit.md) | `function disasm` ignores `--limit` and silently truncates to 10 instructions | low | fixed (unreleased) |
| [005](005-abandoned-jobs-still-run.md) | Jobs whose client timed out or disconnected still run, compounding contention | high (shared bridges) | fixed (unreleased) |
| [006](006-all-reads-serialized-behind-long-jobs.md) | All read-only commands serialize behind long `script_run`/decompile jobs; concurrent reads measured safe (3.6× on 8 threads) | high (shared bridges) | fixed (unreleased) |
| [007](007-empty-output-exit-zero.md) | `program info --json` returned empty output with exit 0 under a ~22-deep queue | medium | not reproduced; guarded (unreleased) |
| [008](008-script-compile-failure-wrong-output.md) | A script compile failure showed another script's output / no javac diagnostics | medium | diagnostics fixed; wrong-class run not reproduced, guarded (unreleased) |
| [009](009-config-defaults-override-explicit-project.md) | Config `default_project`/`default_program` leak into commands given `--project` | medium | `default_program` leak fixed; `default_project` message not reproduced (unreleased) |

"Unreleased" fixes are in the working tree after `c9aefa1` (bridge protocol 3). A running
bridge keeps its old behaviour until it is restarted with the new CLI.

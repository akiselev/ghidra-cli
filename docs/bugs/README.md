# Known bugs

Each file records one reproducible defect with the exact error text, the versions involved, a
source-level cause where known, and a suggested fix.

| ID | Summary | Severity |
|---|---|---|
| [001](001-preflight-program-jobs-block-behind-long-decompiles.md) | Per-invocation `program_info`/`open_program` preflight queues behind long jobs; cheap commands time out after 300 s | high (shared bridges) |
| [002](002-unknown-command-auto-restarts-shared-bridge.md) | An unsupported command auto-restarts a shared bridge, killing other clients' jobs | high (shared bridges) |
| [003](003-decompile-response-buffer-exceeded.md) | `decompile` fails with "Response buffer size exceeded" on ~44–65 KB functions (fixed: 512 MB default, `--max-payload-mb`) | medium, fixed |
| [004](004-function-disasm-ignores-limit.md) | `function disasm` ignores `--limit` and silently truncates to 10 instructions | low |

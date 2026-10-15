# 007: `program info --json` returned empty output with exit code 0 under load

- **Reported:** 2026-10-15, multi-agent trial (via coordinator); queue about 22 deep
- **CLI:** `ghidra 0.2.2` (`c9aefa1`)

## Symptom

One `ghidra program info --json` call printed nothing and exited 0, a silent false success.

## Investigation

- Every error path in `main()` exits 1, and the JSON formatter always emits at least `[]`, so no
  code path was found that prints nothing with exit 0.
- Repro attempt (old CLI against an old bridge, scratch project): 22 concurrent `program info --json`
  behind a 12 s exclusive script, plus 6 with `GHIDRA_CLI_READ_TIMEOUT=3`. Result: 22 × rc 0 with
  output, 6 × rc 1 with a timeout message, 0 empty successes. **Not reproduced.**
- The client accepted any unexpected response `status` (including `shutdown` for a normal command)
  as success with `{}` data.

## Fix (guard)

- An unexpected response status is now an error (`Bridge returned an unexpected response status`).
- Empty output for `--json`/`--pretty` (JSON or compact JSON) is an error with exit 1.
- Output is written with an explicit error check instead of `println!`.

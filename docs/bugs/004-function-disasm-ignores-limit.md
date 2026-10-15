# 004: `function disasm` ignores `--limit` and returns only 10 instructions

- **Observed:** 2026-10-15
- **CLI:** `ghidra 0.2.1`, SHA-256 `51be279bb3c3a35835863c299df11cb21f18efb2fa0c6b3e565ebbc20ae4e48f`

## Symptom

`ghidra function disasm 0x1823fae30 --limit 1000000 --json --project parasolid-c900fa3f430f --program
pskernel.dll` returned only the first 10 instructions of a 558,566-byte function. No warning was printed,
so a caller can easily mistake the prologue for the whole function.

## Expected

Either honour `--limit` (all instructions of the function body up to the limit) or reject the flag.
If the output is truncated, say so in the JSON (for example `"truncated": true`).

## Evidence

`/home/dev/projects/parasolid-re/artifacts/reviews/20261015T-c900fa3f430f-docs-review/size-drivers/faceting-drawing/failures.txt`
item 1; `faceting-drawing/ff_facet.disasm.json`.

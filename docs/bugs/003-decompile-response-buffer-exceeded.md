# 003: `decompile` fails with "Response buffer size exceeded" on ~44–65 KB functions

- **Observed:** 2026-10-15 (reproducible, the same functions fail on retry)
- **CLI:** `ghidra 0.2.1`, SHA-256 `51be279bb3c3a35835863c299df11cb21f18efb2fa0c6b3e565ebbc20ae4e48f`
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll`

## Symptom

```text
Error: Decompilation failed for interval_chain_core_182ffec60 at 182ffec60: Exception while decompiling
182ffec60: Response buffer size exceeded for: pskernel.dll
```

| Address | Function | Body size |
|---|---|---|
| `0x182ffec60` | `interval_chain_core` | 48,869 B (failed twice) |
| `0x1835a9500` | `iss_at` | 49,291 B |
| `0x1812ba510` | `preprocess_multiple_references` | 45,928 B |
| `0x18334d8d0` | `LOP__find_trial_vx_geom_ics` | 44,794 B |
| `0x181be29b0` | `LOP_replace_faces` | 43,969 B |
| `0x180922850` | `hollow_body` | 64,795 B |

This blocks analysis of exactly the largest and most important functions. Other functions of similar
size decompile fine, so the failure depends on the decompiler's output size, not on the body size alone.

## Likely cause (hypothesis)

The message is Ghidra's `DecompInterface` refusing a decompiler response larger than its maximum
payload. `GhidraCliBridge.java` (HEAD `10019ba`) never calls `DecompileOptions.setMaxPayloadMBytes`, so
Ghidra's default limit applies. Large switch-heavy functions with many recovered variables can exceed it.

## Suggested fix

1. Make the payload limit configurable (for example `--max-payload-mb` or `GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB`)
   and set a larger default. Check whether simplification style or syntax-tree toggles also reduce the
   payload.
2. On this error, return a typed error code (not a generic exception string) and suggest the knob, so
   callers can retry with a larger limit or fall back to `disasm`.

## Evidence

`/home/dev/projects/parasolid-re/artifacts/reviews/20261015T-c900fa3f430f-docs-review/`
`blending/dc_182ffec60.rerun.err`, `size-drivers/local-ops/errors.txt`,
`size-drivers/local-ops/dc/{1835a9500,1812ba510,18334d8d0,181be29b0}.err`,
`size-drivers/faceting-drawing/failures.txt` (item 2).

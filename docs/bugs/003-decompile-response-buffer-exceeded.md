# 003: `decompile` fails with "Response buffer size exceeded" on ~44–65 KB functions

- **Observed:** 2026-10-15 (reproducible, the same functions fail on retry)
- **CLI:** `ghidra 0.2.1`, SHA-256 `51be279bb3c3a35835863c299df11cb21f18efb2fa0c6b3e565ebbc20ae4e48f`
- **Project:** `parasolid-c900fa3f430f` / `pskernel.dll`
- **Status:** fixed in 0.2.2 (payload limit configurable, default 512 MB)

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

## Cause

The message comes from Ghidra's `LinkedByteBuffer` (`SoftwareModeling`), which caps one decompiler
response at `DecompileProcess.maxResultSizeMBYtes << 20` bytes. That field is 50 MB unless
`DecompInterface.setOptions()` passes `DecompileOptions.getMaxPayloadMBytes()`
(`SUGGESTED_MAX_PAYLOAD_BYTES = 50`, Ghidra 12.1.2 sources). `GhidraCliBridge.java` never called
`setOptions()`, so every decompile ran with the fixed 50 MB cap. The response holds the C markup tree
and the full high-function p-code, so large functions with many variables and blocks exceed it.

## Fix

- The bridge builds every `DecompInterface` through `newDecompiler(payloadMB)`, which sets a
  `DecompileOptions` with `setMaxPayloadMBytes(payloadMB)`. The default is 512 MB.
- `DecompileOptions` always sends the read-only-memory flag, and its Java default (on) differs from
  the native default the bridge used before (off). The bridge sets `setRespectReadOnly(false)`, so
  decompiler output is byte-identical to earlier builds (checked on `0x18343d480` of
  `parasolid-c900fa3f430f`, 351 KB of C).
- New flag `--max-payload-mb <MB>` on `decompile` and `function decompile` (range 1-2047, since Ghidra
  computes `MB << 20` in an `int`), and env var `GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB`. The flag wins
  over the env var; the env var is clamped to 1-2047.
- When the limit is still hit, the bridge returns error code `decompile_payload_exceeded` (new `code`
  field on error responses; `BridgeError` in `src/ipc/protocol.rs`) and the message names the limit in
  MB and both knobs. The CLI prints `Error [decompile_payload_exceeded]: ...`.
- Tests: unit tests for flag/env resolution and clamping, CLI parsing and range rejection, error-code
  deserialization and downcast; integration test `test_decompile_with_max_payload_flag`.

With the 512 MB default, the five functions below that failed at 50 MB decompile (see the
parasolid-re `next7/ghidra-003` artifacts).

## Evidence

`/home/dev/projects/parasolid-re/artifacts/reviews/20261015T-c900fa3f430f-docs-review/`
`blending/dc_182ffec60.rerun.err`, `size-drivers/local-ops/errors.txt`,
`size-drivers/local-ops/dc/{1835a9500,1812ba510,18334d8d0,181be29b0}.err`,
`size-drivers/faceting-drawing/failures.txt` (item 2).

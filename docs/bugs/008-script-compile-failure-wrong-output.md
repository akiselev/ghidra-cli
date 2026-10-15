# 008: Script compile failure hid javac errors and showed another script's output

- **Reported:** 2026-10-15, multi-agent trial (via coordinator)
- **CLI:** `ghidra 0.2.2` (`c9aefa1`)

## Symptom

`ghidra script run <dir>/M3imprintChains.java` failed to compile (`Memory.getDouble` not found).
The worker reported that it got stdout from `M3imprintDump.java` in the same directory
("dumped 201"), and suspected that a stale or wrong class ran.

## Investigation (scratch project, old and new bridge)

Ghidra builds a script's whole directory as one OSGi bundle and skips files that fail to compile.
Repro: `M3Dump.java` (prints "dumped 201") and `M3Chains.java` (compiles once, then edited to call
`Memory.getDouble`).

Old bridge (`c9aefa1`):
- The broken `M3Chains` fails with only "The class could not be found. It must be the public class
  of the .java file". The javac errors were written to the script's stdout buffer, which the
  error path dropped.
- The next `script run M3Dump.java` returned stdout that **starts with the javac errors of
  `M3Chains`/other broken siblings** ("... hasn't changed, with 2 files failing in previous
  build(s): M3Chains.java:3: error: ...") followed by "dumped 201". So the build output of one
  script leaks into the stdout of another script from the same directory. This is the likely source
  of the report.
- The old v1 class of `M3Chains` was **not** run after the failed rebuild, and no other class ran.
  The wrong-class execution was **not reproduced**.

## Fix

- Build output goes to its own buffer and never to a script's stdout.
- A compile failure fails the job with code `script_compile_error`, the javac diagnostics, and the
  bundle's recorded build error for that file.
- Guards: after loading, the bridge refuses to run if the bundle has a build error recorded for the
  requested file (a stale class), or if the loaded class name is not the file's base name
  (`script_class_mismatch`).
- Script compilation is serialized (the bundle host is shared), so concurrent `--read-only` scripts
  cannot interleave builds.

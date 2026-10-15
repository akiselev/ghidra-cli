# 009: Config `default_project`/`default_program` leak into commands given `--project`

- **Reported:** 2026-10-15, multi-agent trial (via coordinator)
- **CLI:** `ghidra 0.2.2` (`c9aefa1`); config `default_project: motionsolve-mbd-re`,
  `default_program: libfluxprojectcore_64.so`

## Symptoms

1. `ghidra program list --project ci-test` tried to start a bridge with the config's
   `default_program` (from a different project).
2. A "No bridge running for project .../motionsolve-mbd-re" message even though
   `--project parasolid-c900fa3f430f` was given.

## Investigation

1. **Reproduced** with the old CLI. With no bridge running for the named project, the auto-start
   path (`run_with_bridge`, and `ghidra start`) fell back to `config.get_default_program()` without
   checking which project it belongs to. The launch failed with "Requested project program file(s)
   not found: libfluxprojectcore_64.so".
2. **Not reproduced.** Sweeping `status`, `ping`, `jobs`, `cancel`, `program list/info`,
   `function list/get`, `summary`, `stats`, `x-ref`, `graph`, `find`, `dump`, `query`, `tag`,
   `type`, `symbol`, `comment`, `strings`, `memory`, `decompile`, `disasm`, `script list` and
   `diff`, with `--project` both before and after the subcommand, never resolved to the config's
   default project. Every bridge-management command resolves `subcommand --project` → global
   `--project` → config default.

## Fix

The config's `default_program` is used only when the project is the config's `default_project`
(none given, or the same name given). An explicit `GHIDRA_DEFAULT_PROGRAM` environment variable
still applies. Verified: `program list --project scratch-old` with a foreign default program now
starts the bridge in project mode and lists the project's programs.

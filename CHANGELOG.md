# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-18

### Added

- **Automatic full-JDK detection for Ghidra.** Ghidra compiles its bridge script
  at runtime and needs the `jdk.compiler` module, so a JRE (or a `jlink`-trimmed
  image) silently fails. ghidra-cli now resolves a suitable JDK itself —
  requiring `javac`, the `jdk.compiler` module, and major version ≥ Ghidra's
  minimum (21 for Ghidra 12.x) — and hands it to `analyzeHeadless` via
  `JAVA_HOME` rather than relying on Ghidra's PATH-based pick.
  - `--java-home <PATH>` global flag, plus `java_home` config and the
    `GHIDRA_CLI_JAVA_HOME` env var, to override the auto-detected JDK.
- Global `--project` / `--program` flags — usable before any subcommand
  (e.g. `ghidra --project P --program bin function list`); previously these were
  accepted only per-subcommand.
- `ghidra import --no-analyze` — import a binary without running auto-analysis
  (the program is still persisted).
- Config `launch_timeout_secs` (env `GHIDRA_CLI_LAUNCH_TIMEOUT`, default 180s) —
  bounded cap for bridge launch readiness. Env `GHIDRA_CLI_OP_TIMEOUT` caps the
  otherwise-unbounded long-running TCP ops (`analyze` / `import`).

### Changed

- `ghidra import` now runs auto-analysis by default (over TCP) and reports the
  resulting `function_count`. Use `--no-analyze` to skip it.
- `ghidra doctor` and `ghidra setup` now require and verify a **full JDK** (not
  just any Java on `PATH`): `doctor` reports the selected JDK and compiles the
  embedded bridge script as a real health check, surfacing the actual error on
  failure.

### Fixed

- **`ghidra import` no longer hangs on non-trivial binaries.** The bridge now
  launches via `-preScript -noanalysis` (was `-postScript` with full analysis),
  so its TCP socket binds right after the binary loads — before analysis — and
  readiness is fast. Analysis runs afterwards as an unbounded TCP `analyze`
  operation (which also persists the program via `analyzeAll` + `save`),
  decoupling a **bounded launch** (JVM start + OSGi compile + load, capped by
  `launch_timeout_secs`) from **unbounded analysis**.
- Bridge launch/teardown can no longer hang or orphan a JVM. The JVM tree is
  spawned in its own process group and a launch failure/timeout kills the whole
  group (`killpg` on unix, `taskkill /T` on windows) **before** joining the
  output reader threads. Previously the readiness wait capped at 120s while
  analysis kept running, then killed only the `analyzeHeadless` wrapper (not the
  JVM grandchild) and blocked forever joining pipes the surviving JVM held open.
- `ghidra stop` now force-kills the whole bridge process group as a fallback,
  not just the JVM PID.
- `ghidra project delete` now actually deletes the project. It removes the
  Ghidra `<name>.gpr` / `<name>.rep` artifacts (previously it looked for a
  non-existent `<name>` directory and silently deleted nothing) and stops any
  running bridge first so the project lock is released.

## [0.1.10] - 2026-03-11

> Releases 0.1.1–0.1.10 were not documented individually; this section reflects
> the cumulative changes between 0.1.0 and 0.1.10 (the Java-bridge rewrite landed
> across these releases).

### Added

- **Type system enhancements**:
  - `type delete` / `type rename` - CRUD completion for data types
  - `type create-enum` - Create enum types with `--values "KEY=VAL,..."` and `--size`
  - `type typedef` - Create typedef aliases
  - `type add-field` / `type del-field` - Add/remove struct fields with offset and size control
  - `type list` now includes `kind` field (struct/union/enum/typedef/pointer/array/other)
  - `type get` now shows enum members, typedef base type, and `kind` on all types
- **Function signature editing**:
  - `function set-signature` - Set full C-style function signature (parsed by Ghidra's CParser)
  - `function set-return-type` - Set function return type
  - `function set-calling-convention` - Set calling convention (__cdecl, __stdcall, etc.)
  - `function set-var-type` - Retype local variables and parameters in decompiled functions
- **Structured decompile output**:
  - `decompile --with-vars` - Include local variable details (name, type, storage)
  - `decompile --with-params` - Include parameter details (name, type, storage)
- **Internal**: `resolveDataType()` helper in Java bridge for unified type resolution with pointer syntax support

### Changed

- **BREAKING**: Replaced Python bridge (`bridge.py`) with Java bridge (`GhidraCliBridge.java`)
  - Architecture simplified from 3 layers (CLI → Rust daemon → Python bridge) to 2 layers (CLI → Java bridge)
  - No separate Rust daemon process — CLI connects directly to Java bridge via TCP
  - Bridge runs as a GhidraScript inside `analyzeHeadless` JVM
  - Dynamic port binding with port/PID file discovery (`~/.local/share/ghidra-cli/bridge-{hash}.port`)
- **BREAKING**: Removed Python/PyGhidra dependency — only Java 17+ and Ghidra are required
- `ghidra setup` no longer installs PyGhidra
- `ghidra doctor` no longer checks for Python/PyGhidra

### Removed

- All 13 Python scripts (`bridge.py`, `find.py`, `symbols.py`, `types.py`, `comments.py`, `graph.py`, `diff.py`, `patch.py`, `disasm.py`, `stats.py`, `program.py`, `script_runner.py`, `batch.py`)
- Rust daemon process and associated modules (`handler.rs`, `handlers/`, `ipc_server.rs`, `process.rs`, `queue.rs`, `state.rs`, `cache.rs`)
- Dependencies: `remoc`, `interprocess`, `fslock`
- Unix domain socket IPC — replaced with direct TCP to Java bridge

### Security

- Local TCP communication only (localhost binding, no external access)

## [0.1.0] - 2025-01-26

### Added

- Daemon-only architecture with persistent Ghidra connection
- Auto-start daemon on import/analyze/quick commands
- Comprehensive reverse engineering commands:
  - Function analysis (list, decompile, disassemble, calls, xrefs)
  - Symbol management (list, get, create, delete, rename)
  - String analysis and search
  - Type definitions and application
  - Comment management
  - Memory operations
  - Cross-reference analysis
- Search capabilities:
  - String patterns
  - Byte sequences
  - Function names
  - Crypto constants
  - Interesting patterns
- Call graph generation and export
- Binary patching (bytes, NOP, export)
- Script execution (Python and Java)
- Batch operations
- Flexible output formats:
  - Human-readable (default for TTY)
  - Compact JSON (default for pipes)
  - Pretty JSON (--pretty flag)
- Expression-based filtering
- AI agent integration support

### Security

- Local IPC communication only (Unix sockets / named pipes)

[unreleased]: https://github.com/akiselev/ghidra-cli/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/akiselev/ghidra-cli/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/akiselev/ghidra-cli/compare/v0.1.0...v0.1.10
[0.1.0]: https://github.com/akiselev/ghidra-cli/releases/tag/v0.1.0

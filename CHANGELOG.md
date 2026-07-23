# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Responsive control plane with a real job queue.** Socket handling is now split
  from Ghidra program execution. `ping`, `status`, `bridge_info`, `jobs`, and
  `cancel` answer immediately from thread-safe snapshots while a long
  `analyze`/`import`/decompile holds the single Ghidra-owned program lane. Program
  operations get job IDs and wait in a bounded FIFO (256 deep) instead of an
  invisible socket backlog.
- `ghidra jobs [JOB_ID]` — inspect the active job, the queue, and recent history
  (the bridge keeps the last 100 jobs), or one job by ID.
- `ghidra cancel [JOB_ID]` — cooperatively cancel the active job (or a specific
  one). A job that hasn't started is dropped from the queue immediately; a running
  job is cancelled via a per-job `TaskMonitor`.

### Changed

- `ghidra script run` runs a checked-in script by absolute path with real
  positional arguments (everything after `--`) and captured stdout, returning
  `{script, path, stdout, args}`. New `--expect PATH[:MIN_ROWS]` (repeatable) fails
  the job when an output artifact is missing, empty, or short; `--allow-empty`
  permits an expected-but-empty file. Scripts run on the cancellable job lane, so
  `ghidra cancel` works on them.

### Fixed

- Commands issued while the bridge is busy now wait in the queue instead of
  failing with "bridge not responding" — a slow analysis no longer looks like a
  dead bridge.
- Import now treats stale empty `.gpr`/`.rep` project artifacts as uninitialized
  and uses the durable one-shot import path instead of trying to start a
  project-mode bridge that Ghidra rejects because it contains no programs.
- Removed the inert legacy config key `timeout`. Old YAML files containing it
  still load, but the key is dropped when saved and `config set timeout` points
  to the active read, long-operation, connection, and launch timeout controls.
- `patch nop --count N` now NOPs N consecutive instructions (was: silently
  ignored, only the instruction at the address was patched). The client forwards
  the count and the bridge walks instruction by instruction, so variable-length
  ISAs work; if any address in the run has no instruction the whole patch rolls
  back.
- `comment set --comment-type PRE|POST|PLATE` now takes effect (was: always
  `EOL`). The client sent the type under key `type` while the bridge read
  `comment_type`; the client now sends `comment_type` and the bridge still
  accepts the old key as a fallback.

## [0.2.1]

### Fixed

- **`--limit 0` now means "all rows"** (was: returned 0 rows). Both the
  client-side paginator and the bridge request treat `--limit 0` as unlimited,
  matching the bridge's own convention, and it no longer falls back to the
  1000-row default. This makes complete exports
  (`ghidra dump exports --limit 0`, `function list --limit 0`, …) work as
  documented instead of silently writing `[]`.
- **Malformed `--filter` expressions now fail with a clear error** (was:
  the parse error was swallowed and the CLI dumped the *entire unfiltered,
  unlimited* dataset while exiting 0). A bare word like `--filter PK` is
  rejected up front — before any bridge fetch — with a hint to use
  `name~PK` (contains) or `name=~"^PK_"` (regex). The filter DSL is now
  summarized in `--help` for `--filter` and `--limit`.
- **`=~` regex filters are now case-insensitive**, matching the other string
  operators. Field values are lowercased before matching, so an uppercase
  pattern like `name=~"^PK_"` previously matched nothing, silently.
- Filter regexes are compiled once per pattern instead of once per row,
  removing a large constant cost when filtering datasets with millions of
  rows (e.g. 1.9M symbols).

## [0.2.0]

### Added

- **Automatic full-JDK detection for Ghidra.** Ghidra compiles its bridge script
  at runtime and needs the `jdk.compiler` module, so a JRE (or a `jlink`-trimmed
  image) silently fails. ghidra-cli now resolves a suitable JDK itself —
  requiring `javac`, the `jdk.compiler` module, and major version ≥ Ghidra's
  minimum (21 for Ghidra 12.x) — and hands it to `analyzeHeadless` via
  `JAVA_HOME` rather than relying on Ghidra's PATH-based pick. Override with the
  `--java-home <PATH>` global flag, `java_home` config, or `GHIDRA_CLI_JAVA_HOME`.
- Global `--project` / `--program` flags — usable before any subcommand
  (e.g. `ghidra --project P --program bin function list`); previously these were
  accepted only per-subcommand.
- Global `--projects-dir <DIR>` flag (with `ghidra_project_dir` config and
  `GHIDRA_PROJECT_DIR` env) to choose where Ghidra projects are stored.
- `ghidra import --no-analyze` — import a binary without running auto-analysis
  (the program is still persisted).
- `ghidra program export` now supports the built-in Ghidra exporters in addition
  to JSON: `xml`, `c`/`cpp`, `binary`/`bin`, `gzf`, `ascii`/`asm`, `hex`, and
  `html`. Exporters are resolved by class name and 4-arg arity so they keep
  working across Ghidra versions.
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
- The `ilspy-cli` companion tool was extracted into its own repository and is no
  longer part of this workspace.

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
- `ghidra program close`, `program delete`, and `program export` now work — the
  Rust client was sending command names (`close_program`, `delete_program`,
  `export_program`) the Java bridge never registered, so they always errored.
- `--filter`, `--sort`, `--count`, and `--offset` are now honored on all list
  commands (`function list`, `strings list`, `symbol list`, `type list`,
  `query`, `dump`). The bridge only does a literal substring match on the name
  field, so ghidra-cli now fetches the full dataset and applies the real filter
  DSL, sort, pagination, and count client-side.
- Call-graph and callee traversal now find every call within a function body,
  not just calls at its entry point (the reference scan now iterates all
  reference sources in the function body).
- `program export --format binary` and the other native exporters no longer fail
  on Ghidra 12: the `Exporter.export` method is resolved by name + 4-arg arity
  rather than an exact `Program.class` signature that drifted across versions.
- Default project directory no longer breaks on Linux with Ghidra 12.1+, which
  rejects any project location containing a dot-prefixed path component
  (e.g. `~/.cache`). The default now falls back to `~/ghidra-cli-projects` when
  the cache path has a hidden component (macOS/Windows keep their cache-dir
  location).
- `ghidra project delete` now actually deletes the project. It removes the
  Ghidra `<name>.gpr` / `<name>.rep` artifacts (previously it looked for a
  non-existent `<name>` directory and silently deleted nothing) and stops any
  running bridge first so the project lock is released. `ghidra project info`
  likewise reports `Exists` based on those artifacts.

[unreleased]: https://github.com/akiselev/ghidra-cli/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/akiselev/ghidra-cli/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/akiselev/ghidra-cli/releases/tag/v0.2.0

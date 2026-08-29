---
name: ghidra-cli
description: >
    Use ghidra-cli for reverse engineering tasks: binary analysis, decompilation, function inspection, cross-reference analysis, pattern discovery, binary patching, and type system management.
    Activate when the user requests:
    - Binary analysis or reverse engineering
    - Decompilation or disassembly
    - Function listing, inspection, or renaming
    - Cross-reference or call graph analysis
    - String or byte pattern searches
    - Binary patching or modification
    - Ghidra project management
    - Type management (structs, enums, typedefs, struct fields)
    - Function signature editing (return type, calling convention, full signature)
    - Variable retyping in decompiled functions
---

# ghidra-cli Agent Reference

Rust CLI for Ghidra reverse engineering. Binary name: `ghidra`.

## Architecture

```
CLI (Rust/clap) ──TCP──► GhidraCliBridge.java (GhidraScript in Ghidra JVM)
```

- **Direct bridge**: no daemon process. The Java bridge IS the persistent server.
- One bridge per project, keyed by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Import/Analyze/query commands **auto-start** the bridge if not running
- Sequential command processing (Ghidra API is not thread-safe)

## Global Flags

| Flag | Effect |
|------|--------|
| `--json` | Compact JSON output (single line) |
| `--pretty` | Pretty-printed JSON |
| `--project P` / `--program PROG` | Target project/program; global, so they may precede the subcommand |
| `--projects-dir DIR` | Where Ghidra projects are stored (overrides `ghidra_project_dir`) |
| `--java-home PATH` | Full JDK for Ghidra (overrides auto-detection) |
| `-v` / `-vv` / `-vvv` | Log verbosity: warn / info / debug |
| `-q` / `--quiet` | Suppress non-essential stderr |

All flags are global, so `ghidra --project P --program bin function list` works the same as putting them after the subcommand.

**Format auto-detection**: TTY → compact human-readable; pipe → json-compact. Override with `--json`, `--pretty`, or `-o FORMAT`.

Ghidra 12.1+ rejects project dirs with a dot-prefixed component (e.g. `~/.cache`); on Linux the default falls back to `~/ghidra-cli-projects`. Use `--projects-dir` to override.

## Quick Start

```bash
# Fastest path: import runs auto-analysis automatically; bridge starts on demand
ghidra import ./binary --project myproject

# All subsequent queries reuse the running bridge
ghidra function list --project myproject
ghidra decompile main --project myproject
```

## Command Reference

### Bridge Lifecycle

```bash
ghidra start [--project P] [--program PROG]
ghidra stop [--project P]
ghidra restart [--project P] [--program PROG]
ghidra status [--project P]
ghidra ping [--project P]
ghidra jobs [JOB_ID] [--project P]      # bridge queue + recent jobs, or one job by ID
ghidra cancel [JOB_ID] [--project P]    # cooperatively cancel active (or given) job
```

`ping`, `status`, `jobs`, and `cancel` answer on a control plane that stays responsive while a long `analyze`/`import`/decompile occupies the serialized program lane. Queued program operations get job IDs and wait in a bounded FIFO.

### Project Management

```bash
ghidra project create NAME
ghidra project list
ghidra project info [NAME]
ghidra project delete NAME
```

### Import & Analysis

```bash
ghidra import BINARY [--project P] [--program PROG] [--no-analyze] [--detach]
ghidra analyze [--project P] [--program PROG] [--detach]
```

Both auto-start the bridge. `ghidra import` runs auto-analysis by default (and
persists the program); pass `--no-analyze` for a raw import without analysis.
`--detach` returns immediately.

### Program Management

```bash
ghidra program list [--project P]          # alias: prog, programs
ghidra program open --program PROG [--project P]   # --program required by runtime
ghidra program close [--project P]
ghidra program delete --program PROG [--project P]
ghidra program info [--project P]
ghidra program export FORMAT [--project P] [-o OUTPUT]   # FORMAT: json, xml, c/cpp, binary/bin, gzf, ascii/asm, hex, html
ghidra program save [--program PROG] [--project P]
```

**Persistence gotcha**: while the bridge is running, every write command (rename, comment, patch, type/symbol/tag ops, `function create`, etc.) only commits an in-memory Ghidra transaction — it is *not* written to the project's `.rep` folder on disk. The bridge auto-saves after `analyze` completes and when `program open` switches to a different program, but nothing else. This means the Ghidra GUI (which reads straight from disk) won't see pending CLI changes, and — more importantly — `program close` does **not** persist them either; only the bridge process actually exiting does (Ghidra's headless script-execution harness holds an outer transaction open for the bridge's whole lifetime, so an in-place save always fails with "Unable to lock due to active transaction", confirmed empirically). `ghidra program save` gets a real flush by stopping and immediately restarting the bridge against the same program (a few seconds of downtime); `ghidra stop` does the same without restarting. Run one of the two before opening the project in the GUI, or before relying on changes surviving a bridge crash.

**`program save`'s reported success is not fully trustworthy at scale — verify, don't trust, and save incrementally.** Empirically (gb-tennis-cli recovery session): running ~700 uncommitted mutations (renames/comments/symbols) in one long unattended batch, then calling `ghidra program save` once at the end, printed `"Saved (bridge restarted)"` but the reopened project came back with the *original* pre-batch state (function count and comment count both reverted) — total silent data loss despite a success message. Immediately after, the exact same workflow but checkpointed every ~50-60 mutations (`program save` after each small batch, with a `function list --count` check right after each restart) held cleanly across 10+ consecutive checkpoints with zero loss. Root cause not confirmed (plausibly tied to an unrelated crashed process from the failed run rather than batch size itself, but not proven either way) — until it is, treat large uncommitted batches as risky and adopt this pattern for any bulk scripted editing session:
1. Batch mutations in modest chunks (tens, not hundreds).
2. Call `ghidra program save` after each chunk.
3. Immediately re-check state after the restart (`ghidra function list --count`, spot-check a known comment/rename) — don't just trust the "Saved" message text.
4. If a checkpoint's count doesn't match what's expected, stop and investigate before piling on more work over a possibly-reverted base.

### Function Operations

```bash
ghidra function list [QUERY_OPTS]           # aliases: fn, func, functions
ghidra function get TARGET [QUERY_OPTS]     # TARGET = name or 0xADDRESS
ghidra function decompile TARGET [--with-vars] [--with-params] [QUERY_OPTS]
ghidra function disasm TARGET [QUERY_OPTS]
ghidra function calls TARGET [QUERY_OPTS]   # outgoing calls
ghidra function xrefs TARGET [QUERY_OPTS]   # incoming references
ghidra function rename OLD NEW [--project P] [--program PROG]
ghidra function create ADDRESS [NAME] [--project P] [--program PROG]
ghidra function delete TARGET [QUERY_OPTS]
ghidra function set-signature TARGET --signature "int foo(int x, char *y)" [--project P] [--program PROG]
ghidra function set-return-type TARGET --type TYPE [--project P] [--program PROG]
ghidra function set-calling-convention TARGET --convention CC [--project P] [--program PROG]
ghidra function set-var-type TARGET --var VARNAME --type TYPE [--project P] [--program PROG]
ghidra function set-noreturn TARGET [--value true|false] [--project P] [--program PROG]
ghidra function tag add TARGET TAG_NAME [--project P] [--program PROG]
ghidra function tag remove TARGET TAG_NAME [--project P] [--program PROG]
ghidra function tag list [TARGET] [QUERY_OPTS]   # tags on one function, or every tag definition
ghidra function list --tag TAG_NAME [QUERY_OPTS] # filter by tag
```

`function create` auto-disassembles at ADDRESS first if no instruction is there yet — no need to call `disasm-at` first in the common case. `function get`/`function list` output includes `no_return` and `tags` fields.

If `function create` fails, the error carries structured detail (visible with `-vv` or `--json`): an "already exists" error includes the containing function's `name`/`entry_point`/`size`; a `createFunction` rejection includes `has_instruction_at_entry`, `containing_function`, `code_unit_range`, and (if Ghidra threw rather than returned null) `ghidra_exception`.

**`function create`'s auto-disassemble path can still fail even when every precondition looks satisfied, and the failure can be intermittent rather than deterministic.** Confirmed on a completely untouched Game Boy ROM address (`0x3100`): the response showed `auto_disassembled_attempted: true`, `has_instruction_at_entry: true`, `code_unit_is_instruction: true` — a real, valid instruction was disassembled — yet `createFunction()` still threw "Function body must contain the entrypoint". This is not limited to one historically-cursed address either: it hit multiple fresh addresses in the same session. Retrying the *identical* call later (same address, no changes in between) sometimes succeeded on the second attempt with no intervention — so a single failure here does not reliably mean the address is permanently uncreatable. Two things worth doing before giving up on an address:
- Retry the same `function create` call once or twice.
- If it keeps failing, fall back to a `script run` script that calls Ghidra's `disassemble()`/`createFunction()` API directly (see `tools/ghidra-scripts/MakeFunctions.java` in this repo for a working example) — this workaround succeeded on every address tested where the native CLI command failed, including ones that had failed repeatedly via the CLI across multiple prior sessions.

**`function rename OLD NEW` can silently rename the wrong function if `OLD` doesn't exist as an independent function's exact entry point.** When `OLD` (e.g. an address-derived name like `FUN_1234`) doesn't resolve to a function whose entry point is exactly that address — because the address is actually inside another function's body (the "shared/fallthrough code" pattern Ghidra's function-boundary model allows, where a `JP`/`JR` target lands mid-function rather than at a real boundary) — the command does not error. Instead it silently renamed the *containing* function to the new name, discarding its correct original name. This corrupted several real function names during a bulk recovery replay before being caught by an independent diff against expected names. Before renaming anything derived from an address rather than a known-good current name, verify first:
```bash
ghidra function get 0xADDR --json   # check the returned "entry_point" against ADDR
```
If `entry_point` matches `ADDR` exactly, `function rename` is safe. If it doesn't match (the address is inside a different, larger function), use `ghidra symbol create 0xADDR NAME` instead to label the address without touching the containing function's name.

### Top-level Shortcuts

```bash
ghidra decompile TARGET [--with-vars] [--with-params] [QUERY_OPTS]   # aliases: decomp, dec
ghidra disasm TARGET [-n COUNT] [QUERY_OPTS]   # TARGET = name or 0xADDRESS; aliases: disassemble, dis
ghidra disasm-at ADDRESS [--count N] [--project P] [--program PROG]
ghidra clear START:END [--to-data] [--disasm-at ADDR] [--project P] [--program PROG]
```

`disasm-at` disassembles at ADDRESS if nothing is there yet (the common case for computed-jump targets static analysis never reached) and reports `ok`/`landed` booleans plus the resulting instructions — check `landed`, not just `ok`: `disassemble()` can report success with no instruction actually at the target.

`clear` wraps `clearCodeUnits` for stale/wrong instructions (e.g. auto-analysis linearly disassembled through inline data): `clear START:END --to-data` clears and leaves the range as undefined data; `clear START:END --disasm-at ADDR` clears then immediately re-disassembles at a precise address in one call, reporting `ok`/`landed` the same way as `disasm-at`.

`--with-vars` includes local variable details (name, type, storage) in the response.
`--with-params` includes parameter details (name, type, storage) in the response.
Both flags add structured data alongside the decompiled C code; use `--json` to see the full output.

### String Operations

```bash
ghidra strings list [QUERY_OPTS]            # aliases: string, str
ghidra strings refs STRING [QUERY_OPTS]     # xrefs to string
```

### Symbol Operations

```bash
ghidra symbol list [QUERY_OPTS]             # aliases: sym, symbols
ghidra symbol get NAME [QUERY_OPTS]
ghidra symbol create ADDRESS NAME [--project P] [--program PROG]
ghidra symbol delete NAME [--address ADDR] [--all] [QUERY_OPTS]
ghidra symbol rename OLD NEW [--address ADDR] [--all] [--filter EXPR] [--project P] [--program PROG]
```

Ghidra auto-generates names (`caseD_XX`, `LAB_XXXX`, ...) that are commonly reused across unrelated addresses program-wide. Because of this, `symbol delete`/`symbol rename` refuse to guess when `NAME`/`OLD` matches more than one symbol: pass `--address 0xADDR` (or `--filter`, e.g. `--filter 'address=0xc200'`) to pick the one you mean, or `--all` to explicitly affect every match. A name matching exactly one symbol needs no disambiguation.

### Memory Operations

```bash
ghidra memory map [QUERY_OPTS]              # alias: mem
ghidra memory read ADDRESS SIZE [QUERY_OPTS]
ghidra memory write ADDRESS BYTES [--project P] [--program PROG]
ghidra memory search PATTERN [QUERY_OPTS]
```

### Cross-References

```bash
ghidra x-ref to ADDRESS [QUERY_OPTS]        # aliases: xref, xrefs, crossref
ghidra x-ref from ADDRESS [QUERY_OPTS]
ghidra x-ref list TARGET [QUERY_OPTS]   # refs both to and from the target
```

`x-ref list` takes a target (name, `0xADDR`, or `FUN_<hex>`) and returns references in both directions. If the target is a function, the "from" side scans the whole function body, not just its entry.

### Type Operations

```bash
ghidra type list [QUERY_OPTS]               # alias: types  (includes "kind" field: struct/union/enum/typedef/pointer/array/other)
ghidra type get NAME [QUERY_OPTS]           # shows struct fields, enum members, typedef base type, kind
ghidra type create NAME [--project P] [--program PROG]              # create empty struct (bare identifier only, NOT a C struct definition -- use `type add-field` to build it)
ghidra type apply ADDRESS TYPE_NAME [--force] [--project P] [--program PROG]  # --force/--clear-conflicting clears a conflicting data unit first
ghidra type delete NAME [--project P] [--program PROG]              # alias: rm
ghidra type rename OLD NEW [--project P] [--program PROG]           # alias: mv
ghidra type create-enum NAME --values "A=0,B=1,C=2" [--size 4] [--project P] [--program PROG]
ghidra type typedef NAME BASE_TYPE [--project P] [--program PROG]   # create type alias
ghidra type add-field STRUCT_NAME --name FIELD --type TYPE [--offset N] [--size N] [--project P] [--program PROG]
ghidra type del-field STRUCT_NAME --name FIELD [--project P] [--program PROG]
```

A `type apply` "Conflicting data exists" error carries structured detail (`-vv`/`--json`): the conflicting unit's kind (instruction/data), type name, and address range. Pass `--force` to clear it and retry in one call instead of a manual `clear` first.

### Comment Operations

```bash
ghidra comment list [QUERY_OPTS]            # alias: comments
ghidra comment get ADDRESS [QUERY_OPTS]
ghidra comment set ADDRESS TEXT [--comment-type TYPE] [--project P] [--program PROG]
ghidra comment set ADDRESS --stdin [--comment-type TYPE] [--project P] [--program PROG]         # read text from stdin
ghidra comment set ADDRESS --text-file PATH [--comment-type TYPE] [--project P] [--program PROG] # read text from a file
ghidra comment delete ADDRESS [QUERY_OPTS]
```

`--comment-type` takes `EOL` (default), `PRE`, `POST`, or `PLATE`.

Prefer `--stdin`/`--text-file` over a TEXT shell argument for anything programmatically generated: a shell argument is subject to metacharacter expansion (backticks, `$…`) *before* ghidra-cli ever sees the string, which can silently corrupt the comment while `comment set` still reports success. `--stdin`/`--text-file` bypass the shell entirely.

### Search / Find

```bash
ghidra find string PATTERN [QUERY_OPTS]     # alias: search
ghidra find bytes HEX [QUERY_OPTS]
ghidra find function PATTERN [QUERY_OPTS]   # glob patterns
ghidra find calls FUNCTION [QUERY_OPTS]
ghidra find crypto [QUERY_OPTS]             # detect AES/SHA/RSA constants
ghidra find interesting [QUERY_OPTS]        # suspicious patterns
```

### Graph / Call Graph

```bash
ghidra graph calls [QUERY_OPTS]             # aliases: callgraph, cg
ghidra graph callers FUNCTION [--depth N] [QUERY_OPTS]
ghidra graph callees FUNCTION [--depth N] [QUERY_OPTS]
ghidra graph export FORMAT [QUERY_OPTS]     # FORMAT: dot, json
```

### Diff

```bash
ghidra diff programs PROG1 PROG2 [--project P] [--format F]
ghidra diff functions FUNC1 FUNC2 [--project P] [--format F]
```

### Dump / Export

```bash
ghidra dump imports [QUERY_OPTS]            # alias: export
ghidra dump exports [QUERY_OPTS]
ghidra dump functions [QUERY_OPTS]
ghidra dump strings [QUERY_OPTS]
```

### Patch

```bash
ghidra patch bytes ADDRESS HEX [--project P] [--program PROG]
ghidra patch nop ADDRESS [--count N] [--project P] [--program PROG]
ghidra patch export -o OUTPUT [--project P] [--program PROG]
```

`--count N` NOPs N consecutive instructions from ADDRESS (default 1), walking instruction by instruction. If any address in the run has no instruction, the whole patch rolls back.

### Script Execution

```bash
ghidra script run PATH [--expect PATH[:MIN_ROWS]]... [--allow-empty] [--project P] [--program PROG] [-- ARGS...]
ghidra script run - [-- ARGS...] < script.java   # read Java source from stdin for a one-off
ghidra script python CODE [--project P] [--program PROG]   # disabled by design; use `script run -`
ghidra script java CODE [--project P] [--program PROG]     # disabled by design; use `script run -`
ghidra script list
```

`script run` resolves PATH to an absolute location, forwards the args after `--` to the script as real positional arguments, and captures stdout in the response (`{script, path, stdout, args}`). `--expect PATH[:MIN_ROWS]` (repeatable) fails the job if that artifact is missing, empty, or below MIN_ROWS; `--allow-empty` lets an expected artifact exist while empty. Scripts run on the cancellable job lane, so `ghidra cancel` works on them.

`script run -` reads a `public class <Name> extends GhidraScript { ... }` body from stdin for a throwaway one-off that doesn't warrant a checked-in file — it's staged to a temp file server-side and compiled through the exact same path as `script run PATH`. `script python`/`script java` (true inline eval) stay disabled on purpose (see `ghidra doctor`): every script is required to go through Ghidra's normal compile gate rather than a second, less-sandboxed eval path.

**Put `--json`/`--pretty`/other global flags *before* the subcommand when using `script run -- ARGS`.** Everything after `--` is forwarded verbatim to the script as positional args — `ghidra script run PATH -- addr1 addr2 --json` passes the literal string `--json` as a third script argument, not as a CLI flag, which broke a script that tried to parse every arg as a hex address (`For input string: "--json" under radix 16`). Use `ghidra --json script run PATH -- addr1 addr2` instead.

### Batch

```bash
ghidra batch SCRIPT_FILE [--project P] [--program PROG]
```

Batch file: one subcommand per line (without `ghidra` prefix), `#` comments.

### Universal Query

```bash
ghidra query DATA_TYPE [QUERY_OPTS]
```

DATA_TYPE: `functions`, `strings`, `imports`, `exports`, `memory`.

### Statistics & Info

```bash
ghidra summary [QUERY_OPTS]       # alias: info
ghidra stats [QUERY_OPTS]
```

### Configuration

```bash
ghidra init                       # create config
ghidra doctor                     # check installation
ghidra version
ghidra config list
ghidra config get KEY
ghidra config set KEY VALUE       # keys: ghidra_install_dir, ghidra_project_dir, default_program, default_project, default_output_format, default_limit, launch_timeout_secs
ghidra config reset
ghidra set-default KIND VALUE     # KIND: program, project
ghidra setup [--version V] [--dir D] [--force]
```

Bridge wait controls are environment variables: `GHIDRA_CLI_READ_TIMEOUT` for
normal commands, `GHIDRA_CLI_OP_TIMEOUT` for analyze/import, and
`GHIDRA_CLI_CONNECT_DEADLINE` for connection establishment. The legacy config
key `timeout` is ignored when loading old files and rejected by `config set`.

## Common Query Options (QUERY_OPTS)

All query commands accept these:

| Option | Description |
|--------|-------------|
| `--project P` | Project name or path |
| `--program PROG` | Program within project |
| `--filter EXPR` | Filter expression |
| `--fields LIST` | Comma-separated fields to return |
| `-o FORMAT` | Output format |
| `--limit N` | Max results |
| `--offset N` | Skip first N |
| `--sort FIELDS` | Sort: comma-separated, prefix `-` for descending |
| `--count` | Return count only |
| `--json` | Shorthand for `--format=json` |

## Output Formats

| Value | Use |
|-------|-----|
| `compact` | Default for TTY. One line per item. |
| `full` | Multi-line labeled blocks |
| `json` | Pretty JSON |
| `json-compact` | Default for pipes. Single-line JSON. |
| `json-stream` / `ndjson` | One JSON object per line |
| `csv` / `tsv` | Delimited with header |
| `table` | ASCII box-drawn table |
| `count` | Number only |
| `ids` / `minimal` | Address/name only, one per line |
| `tree` | Indented hierarchy |
| `hex` | Hex dump |
| `asm` | Assembly |
| `c` | C pseudocode |

## Filter Expressions

```bash
# Numeric
--filter "size > 100"
--filter "size >= 50"

# String
--filter "name ~ 'crypt'"

# Combined
--filter "size > 100 AND name ~ 'main'"
--filter "name != 'main'"
```

Operators: `=`, `!=`, `>`, `>=`, `<`, `<=`, `~` (contains), `^` (starts with), `$` (ends with), `=~` (regex), `AND`, `OR`, `NOT`, `IN`, `EXISTS`.

## Agent Best Practices

### 1. Count-First Pattern

Always check result volume before fetching:

```bash
ghidra function list --count --project P
# If manageable:
ghidra function list --limit 50 --fields name,address,size --project P
```

### 2. Aggressive Filtering

Pre-filter server-side, not client-side:

```bash
# GOOD
ghidra function list --filter "size > 1000" --project P
# BAD
ghidra function list --project P  # then filter in agent code
```

### 3. Field Selection

Request only needed fields:

```bash
ghidra function list --fields name,address --json --project P
```

### 4. Set Defaults

Avoid repeating `--project` and `--program`:

```bash
ghidra set-default project myproject
ghidra set-default program mybinary
# Now: ghidra function list  (no flags needed)
```

### 5. Save Incrementally, Verify Don't Trust

For any session doing more than a handful of write operations (bulk renames, scripted recovery/replay, batch comment annotation): checkpoint with `ghidra program save` every few dozen mutations rather than once at the end, and re-verify actual state after each save (`function list --count`, a spot-check `function get`/`comment get` on something just changed) instead of trusting the command's printed "Saved" status. See the Persistence gotcha note under Program Management — a single large uncommitted batch was silently lost in full despite a successful-looking save, while the same work checkpointed in small chunks was not. This matters most for scripted/agent-driven bulk edits, where nothing stops until someone checks.

For any workflow that reconstructs known state programmatically (e.g. replaying a log of past commands, bulk-importing names from documentation), don't just trust that each individual command reported success — after the run, independently diff the *actual* resulting state (`function list --fields name,address`) against the expected mapping. `function rename`'s silent-mismatch failure mode (above) produces no error at the time it happens; it was only caught by this kind of after-the-fact diff.

## .NET Warning

`ghidra decompile` prints a warning when the output looks like .NET managed code
(e.g. `halt_baddata()` or a `.NET CLR Managed Code` marker):

> "This appears to be .NET managed code. Ghidra cannot decompile .NET IL bytecode. Consider using a .NET decompiler (e.g., ilspy-cli) for better results."

Ghidra won't produce useful output for IL. Reach for a dedicated .NET
decompiler instead. `ilspy-cli` is a separate tool, not part of ghidra-cli.

## Analysis Workflow

```bash
# 1. Import and analyze
ghidra import ./target.exe --project analysis
ghidra analyze --project analysis

# 2. Recon
ghidra summary --project analysis
ghidra function list --count --project analysis
ghidra function list --filter "NOT name ^ 'FUN_'" --fields name,address,size --limit 30 --project analysis

# 3. Investigate
ghidra decompile main --project analysis
ghidra decompile main --with-vars --with-params --json --project analysis  # structured output
ghidra find crypto --project analysis
ghidra find string "password" --project analysis

# 4. Deep dive
ghidra graph callers suspicious_func --depth 3 --project analysis
ghidra x-ref to 0x401000 --project analysis
ghidra function disasm 0x401000 --project analysis

# 5. Type annotation (improves decompile output)
ghidra type create MyStruct --project analysis
ghidra type add-field MyStruct --name fd --type int --project analysis
ghidra type add-field MyStruct --name flags --type uint --project analysis
ghidra type create-enum ErrorCode --values "OK=0,ENOENT=2,EPERM=1" --project analysis
ghidra type typedef HANDLE void --project analysis
ghidra function set-return-type main --type int --project analysis
ghidra function set-signature parse_data --signature "int parse_data(char *buf, int len)" --project analysis
ghidra function set-var-type main --var local_10 --type "MyStruct *" --project analysis
ghidra decompile main --project analysis  # re-decompile with new types applied

# 6. Patch
ghidra patch nop 0x401234 --count 3 --project analysis
ghidra patch export -o patched.exe --project analysis
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Ghidra installation path |
| `GHIDRA_PROJECT_DIR` | Base directory for projects |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK for Ghidra (overrides auto-detection) |
| `GHIDRA_DEFAULT_PROJECT` | Default `--project` for `ghidra query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default `--program` for `ghidra query` and program auto-selection |
| `GHIDRA_CLI_CONFIG` | Override config path |
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Cap on bridge launch readiness (default 180s) |
| `GHIDRA_CLI_OP_TIMEOUT` | Cap on long `analyze`/`import` ops (default unbounded) |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Ghidra-side decompiler limit, seconds; `0` = unbounded (default unbounded) |
| `GHIDRA_CLI_READ_TIMEOUT` | Per-request socket read timeout; `0` = indefinite (default 300s) |
| `GHIDRA_CLI_CONNECT_DEADLINE` | Retry window for connecting to a (re)starting bridge (default 60s) |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Grace period to drain jobs before force-kill; `0` = indefinite (default 300s) |

## File Locations

| File | Purpose |
|------|---------|
| `~/.local/share/ghidra-cli/bridge-{md5}.port` | TCP port for running bridge |
| `~/.local/share/ghidra-cli/bridge-{md5}.pid` | Bridge process PID |
| `~/.config/ghidra-cli/config.yaml` | Configuration |
| `~/.config/ghidra-cli/scripts/GhidraCliBridge.java` | Materialized Java bridge script |
| `~/.local/share/ghidra-cli/ghidra-cli.log` | Debug log |

## Error Recovery

| Problem | Fix |
|---------|-----|
| "No project specified" | Add `--project NAME` or `ghidra set-default project NAME` |
| "Bridge not responding" | `ghidra stop --project P` then retry (auto-starts) |
| "Ghidra installation not configured" | `ghidra setup` or set `GHIDRA_INSTALL_DIR` |
| Function not found | Use `ghidra find function "*pattern*"` |
| Slow first command | Normal: bridge startup + analysis takes seconds |

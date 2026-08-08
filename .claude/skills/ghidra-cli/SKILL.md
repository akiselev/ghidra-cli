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
```

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
```

### Top-level Shortcuts

```bash
ghidra decompile TARGET [--with-vars] [--with-params] [QUERY_OPTS]   # aliases: decomp, dec
ghidra disasm TARGET [-n COUNT] [QUERY_OPTS]   # TARGET = name or 0xADDRESS; aliases: disassemble, dis
```

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
ghidra symbol delete NAME [QUERY_OPTS]
ghidra symbol rename OLD NEW [--project P] [--program PROG]
```

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
ghidra type create DEFINITION [--project P] [--program PROG]        # create empty struct
ghidra type apply ADDRESS TYPE_NAME [--project P] [--program PROG]
ghidra type delete NAME [--project P] [--program PROG]              # alias: rm
ghidra type rename OLD NEW [--project P] [--program PROG]           # alias: mv
ghidra type create-enum NAME --values "A=0,B=1,C=2" [--size 4] [--project P] [--program PROG]
ghidra type typedef NAME BASE_TYPE [--project P] [--program PROG]   # create type alias
ghidra type add-field STRUCT_NAME --name FIELD --type TYPE [--offset N] [--size N] [--project P] [--program PROG]
ghidra type del-field STRUCT_NAME --name FIELD [--project P] [--program PROG]
```

### Tag Operations

Function tags organize large codebases: named, program-scoped labels with an
optional comment, attachable to any number of functions.

```bash
ghidra tag list [--function TARGET] [QUERY_OPTS]   # alias: tags — all tags (name, comment, use_count), or one function's tags
ghidra tag get NAME [QUERY_OPTS]                   # alias: show — member functions of a tag (rows: name, address)
ghidra tag create NAME [--comment TEXT] [--project P] [--program PROG]
ghidra tag delete NAME [--project P] [--program PROG]                  # alias: rm — detaches from ALL functions; reports use_count + functions_affected
ghidra tag rename OLD NEW [--project P] [--program PROG]               # alias: mv — global; errors if NEW exists (no implicit merge)
ghidra tag set-comment NAME COMMENT [--project P] [--program PROG]     # "" clears
ghidra tag add TARGET TAG... [--no-create] [--project P] [--program PROG]    # auto-creates missing tags; reports added/created/already_present
ghidra tag remove TARGET TAG... [--project P] [--program PROG]         # reports removed/not_present; idempotent
ghidra tag remove TARGET --all [--project P] [--program PROG]          # detach every tag
ghidra function list --tag NAME [--tag NAME2] [QUERY_OPTS]             # server-side filter; multiple --tag = AND
ghidra function list --untagged [QUERY_OPTS]                           # functions with no tags (triage complement)
```

Semantics agents should know:
- Tag names are **case-sensitive** (`Crypto` ≠ `crypto`). Unknown-tag errors
  include a `Did you mean ...?` hint and exit **nonzero** — check `ghidra tag
  list` first (or use `--filter`) in speculative loops. A no-match `--filter`
  exits 0 with empty output; an unknown `--tag` exits nonzero.
- `tag add`/`remove` are idempotent: already-attached / not-present tags are
  reported in the response, never errors — safe to retry.
- Function rows (`function list`/`get`) carry a sorted `tags` array (present
  even when empty), so `--fields name,address,tags` and `--filter "tags ~
  'crypto'"` work. DSL `~`/`^`/`$`/`=~`/`in` are case-insensitive on tags;
  `=`/`!=` are exact. In CSV output, tag arrays join with `;`.
- Names cannot be empty or contain `,` or `;` (rejected at creation; odd names
  created in the Ghidra GUI remain attachable/removable/deletable).
- Names with spaces work but cannot be used in `ghidra batch` files (whitespace
  tokenizer, no quoting).
- External functions are out of scope for tag membership operations: a tag
  applied to externals in the Ghidra GUI may show a higher `use_count` in
  `tag list` than `tag get`'s member count.

Typical agent workflow:

```bash
# Define a taxonomy (comments document meaning for future sessions)
ghidra tag create crypto --comment "Key schedule, cipher rounds, RNG"
ghidra tag create reviewed --comment "Decompiled and understood"

# Triage and tag
ghidra tag add FUN_00401a20 crypto
ghidra tag add aes_key_expand crypto reviewed

# Bulk via batch (one process, one bridge connection; bare tag names only)
printf 'tag add FUN_00402000 network\ntag add parse_packet network reviewed\n' > triage.batch
ghidra batch triage.batch

# Drive the next pass off the taxonomy
ghidra tag list                              # names, comments, use counts
ghidra tag get network                       # member functions (rows)
ghidra function list --tag network --filter "size > 200" --fields name,address,tags
ghidra function list --untagged --limit 20   # what's left to triage
ghidra tag remove parse_packet wip
```

### Comment Operations

```bash
ghidra comment list [QUERY_OPTS]            # alias: comments
ghidra comment get ADDRESS [QUERY_OPTS]
ghidra comment set ADDRESS TEXT [--comment-type TYPE] [--project P] [--program PROG]
ghidra comment delete ADDRESS [QUERY_OPTS]
```

`--comment-type` takes `EOL` (default), `PRE`, `POST`, or `PLATE`.

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
ghidra script python CODE [--project P] [--program PROG]
ghidra script java CODE [--project P] [--program PROG]
ghidra script list
```

`script run` resolves PATH to an absolute location, forwards the args after `--` to the script as real positional arguments, and captures stdout in the response (`{script, path, stdout, args}`). `--expect PATH[:MIN_ROWS]` (repeatable) fails the job if that artifact is missing, empty, or below MIN_ROWS; `--allow-empty` lets an expected artifact exist while empty. Scripts run on the cancellable job lane, so `ghidra cancel` works on them.

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

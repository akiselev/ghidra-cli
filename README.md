# Ghidra CLI

A Rust CLI for automating Ghidra reverse engineering tasks. Usable directly by hand or driven by an AI coding agent like Claude Code.

## Features

- **Direct bridge architecture** - CLI connects directly to a Java bridge running inside Ghidra's JVM
- **Auto-start bridge** - Import/analyze commands automatically start the bridge
- **Fast queries** - Sub-second response times with Ghidra kept in memory
- **Program analysis** - Functions, symbols, types, strings, cross-references
- **Type system** - Create/edit structs, enums, typedefs; add/remove struct fields
- **Function signatures** - Edit return types, calling conventions, full C signatures; retype variables
- **Binary patching** - Modify bytes, NOP instructions, export patches
- **Call graphs** - Generate caller/callee graphs, export to DOT format
- **Search capabilities** - Find strings, bytes, functions, crypto patterns
- **Script execution** - Run Java/Python Ghidra scripts, inline or from files
- **Batch operations** - Execute multiple commands from a file
- **Responsive job control** - Long analyses run on a serialized program lane while `ping`, `status`, `jobs`, and `cancel` stay live on a separate control plane
- **Flexible output** - Human-readable, JSON, or pretty JSON formats
- **Filtering** - Expression-based filtering with a small DSL (e.g., `size > 100 AND name ~ 'crypt'`)

## Architecture

```
┌─────────────────┐         ┌──────────────────────────────────────┐
│   CLI Command   │──TCP──▶ │  GhidraCliBridge.java                │
│   ghidra ...    │         │  (GhidraScript in analyzeHeadless)   │
│   --project X   │         │  ServerSocket on localhost:dynamic   │
└─────────────────┘         └──────────────────────────────────────┘
```

The CLI connects directly to a Java bridge running inside Ghidra's JVM. Ghidra loads once and stays resident, so one process holds all state: a rename or an applied type sticks for the next command instead of resetting each invocation, and queries return in-process with no per-command JVM startup. The bridge auto-starts on demand — any command brings it up, so you never launch it by hand.

Each project gets its own bridge process and port file, so you can analyze several binaries at once. The only runtime dependencies are Ghidra and a JDK — no Python/PyGhidra.

## Installation

### From Source

```bash
git clone https://github.com/akiselev/ghidra-cli
cd ghidra-cli
cargo install --path .
```

### Requirements

- **Ghidra 11+** - Download from [ghidra-sre.org](https://ghidra-sre.org), or run `ghidra setup` to fetch it
- **A full JDK** - not a JRE. Ghidra compiles the bridge script at runtime, so it needs `javac` and the `jdk.compiler` module. Ghidra 12.x wants JDK 21; older releases accept JDK 17. `ghidra doctor` finds a suitable JDK and compiles the bridge as a health check.
- **Rust 1.70+** - For building from source

Point the CLI at your Ghidra install (skip this if you used `ghidra setup`):
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Or store it in config:
ghidra config set ghidra_install_dir /path/to/ghidra
```

`ghidra-cli` picks the JDK itself and passes it to Ghidra, so you don't have to
juggle `PATH`. Override the choice with the global `--java-home` flag, the
`java_home` config key, or `GHIDRA_CLI_JAVA_HOME`.

## Quick Start

```bash
# Check installation
ghidra doctor

# Import a binary. This starts the bridge and runs auto-analysis in one step.
ghidra import ./binary --project myproject --program mybinary

# Query functions (uses the running bridge)
ghidra function list

# Decompile a function
ghidra decompile main

# Find interesting strings
ghidra find string "password"

# Get cross-references
ghidra x-ref to 0x401000

# Generate call graph
ghidra graph callers main --depth 3
```

## Global Flags

These work before any subcommand, so you can set them once for a whole invocation:

```bash
ghidra --project P --program bin function list   # --project/--program are global
```

| Flag | Effect |
|------|--------|
| `--project <P>` | Project name or path |
| `--program <PROG>` | Program within the project |
| `--projects-dir <DIR>` | Where Ghidra projects live (default: a cache dir; overrides `ghidra_project_dir`) |
| `--java-home <PATH>` | Full JDK for Ghidra to use (must be a JDK, not a JRE) |
| `--json` | Compact JSON output |
| `--pretty` | Pretty-printed JSON |
| `-v` / `-vv` / `-vvv` | Log verbosity: warn / info / debug |
| `-q` / `--quiet` | Suppress non-essential output |

Ghidra 12.1+ rejects project directories that contain a dot-prefixed component
(such as `~/.cache`), so on Linux the default falls back to
`~/ghidra-cli-projects`. Use `--projects-dir` to put projects wherever you like.

## Commands

### Project & Program Management
```bash
ghidra project create <name>           # Create project
ghidra project list                    # List projects
ghidra project info [<name>]           # Show project info
ghidra project delete <name>           # Delete project (removes .gpr/.rep, stops its bridge)
ghidra import <binary> --project <p>   # Import + auto-analyze (bridge auto-starts)
ghidra import <binary> --no-analyze    # Import only, skip analysis (still persisted)
ghidra import <binary> --detach        # Return immediately; bridge keeps importing
ghidra analyze --project <p>           # (Re)run analysis on an imported program
```

### Function Analysis
```bash
ghidra function list                   # List all functions
ghidra function list --filter "size > 100"  # Filter by size
ghidra decompile <name-or-addr>        # Decompile function
ghidra decompile main --with-vars --with-params  # Include variable/param details
ghidra disasm <address> --instructions 20  # Disassemble instructions
ghidra function set-signature <func> --signature "int foo(int x, char *y)"
ghidra function set-return-type <func> --type void
ghidra function set-calling-convention <func> --convention __cdecl
ghidra function set-var-type <func> --var local_10 --type "MyStruct *"
```

Decompilation has no native time limit by default, so large valid functions are
not aborted after 30 seconds. Set `GHIDRA_CLI_DECOMPILE_TIMEOUT` to a positive
number of seconds to impose a Ghidra-side limit; `0` means unbounded. The socket
wait follows the long-operation policy controlled by `GHIDRA_CLI_OP_TIMEOUT`,
which is also unbounded by default.

### Symbols & Types
```bash
ghidra symbol list                     # List symbols
ghidra symbol create <addr> <name>     # Create symbol
ghidra symbol rename <old> <new>       # Rename symbol
ghidra type list                       # List data types (with kind: struct/enum/typedef/...)
ghidra type get <name>                 # Get type details (fields, enum members, typedef base)
ghidra type create <name>              # Create empty struct
ghidra type add-field <struct> --name fd --type int   # Add struct field
ghidra type del-field <struct> --name fd              # Remove struct field
ghidra type create-enum <name> --values "A=0,B=1"     # Create enum
ghidra type typedef <name> <base_type>                # Create typedef alias
ghidra type rename <old> <new>         # Rename type
ghidra type delete <name>              # Delete type
```

### Cross-References
```bash
ghidra x-ref to <address>              # References TO address
ghidra x-ref from <address>            # References FROM address
```

### Search
```bash
ghidra find string "pattern"           # Find strings
ghidra find bytes "90 90 90"           # Find byte patterns
ghidra find function "*crypt*"         # Find functions by name
ghidra find crypto                     # Find crypto constants
ghidra find interesting                # Find interesting patterns
```

### Call Graphs
```bash
ghidra graph calls                     # Full call graph
ghidra graph callers <func>            # Who calls this? (--depth optional)
ghidra graph callees <func>            # What does this call? (--depth optional)
ghidra graph export dot                # Export to DOT format
```

### Binary Patching
```bash
ghidra patch bytes <addr> "90 90"      # Patch bytes
ghidra patch nop <addr> --count 5      # NOP out instructions
ghidra patch export -o patched.bin     # Export patched binary
```

`patch nop --count N` NOPs N consecutive instructions starting at the address
(default 1), walking instruction by instruction so variable-length ISAs work. If
any address in the run has no instruction, the whole patch rolls back untouched.

### Comments
```bash
ghidra comment get <address>           # Get comment
ghidra comment set <addr> "note" --comment-type EOL  # Set comment
ghidra comment list                    # List all comments
```

`--comment-type` accepts `EOL` (default), `PRE`, `POST`, or `PLATE`.

### Scripts
```bash
ghidra script list                     # List available scripts
ghidra script run myscript.py          # Run a script file
ghidra script run report.py -- arg1 arg2   # Pass positional args after --
ghidra script run dump.py --expect out.csv:10   # Fail unless out.csv has >=10 rows
ghidra script python "print(currentProgram)"   # Inline Python
ghidra script java "println(currentProgram);"   # Inline Java
```

`script run` resolves the path to an absolute location, forwards the args after
`--` to the script, and captures its stdout in the response. Use `--expect
PATH[:MIN_ROWS]` (repeatable) to make the job fail when an output artifact is
missing, empty, or short, and `--allow-empty` to permit an expected-but-empty
file.

### Batch Operations
```bash
ghidra batch commands.txt              # Run commands from file
```

### Statistics
```bash
ghidra stats                           # Program statistics
ghidra summary                         # Program summary
```

## Bridge Management

The bridge keeps Ghidra loaded in memory. It starts automatically when needed, but you can also control it manually:

```bash
# Start bridge with a program loaded
ghidra start --project myproject --program mybinary

# Check bridge status
ghidra status --project myproject

# Inspect active, queued, and recent jobs (or one job by ID)
ghidra jobs --project myproject
ghidra jobs 42 --project myproject

# Cooperatively cancel the active job, or select a queued/running job by ID
ghidra cancel --project myproject
ghidra cancel 42 --project myproject

# All commands use the bridge automatically
ghidra function list --project myproject    # Fast!
ghidra decompile main --project myproject   # Fast!

# Stop bridge
ghidra stop --project myproject

# Restart with different program
ghidra restart --project myproject --program otherbinary
```

The bridge handles networking and lifecycle controls independently from Ghidra
program access. Program operations remain serialized on one Ghidra-owned thread,
but `ping`, `status`, `jobs`, `cancel`, and drain requests remain responsive while
analysis or another long operation is running. Queued program operations receive
job IDs and wait in an explicit bounded FIFO rather than an invisible socket
backlog.

### Multi-Project Support

Each project gets its own bridge process and port file, allowing concurrent analysis:

```bash
# Work on multiple projects simultaneously
ghidra import ./binary_a --project projA
ghidra analyze --project projA --program binary_a
ghidra import ./binary_b --project projB
ghidra analyze --project projB --program binary_b

# Query each independently
ghidra function list --project projA
ghidra function list --project projB
```

## Output Formats

Default output is human-readable when connected to a terminal. When piped (non-TTY), output auto-detects to compact JSON for machine consumption. Use flags to override:

- **Default (TTY)**: Compact human-readable format (designed for both humans and AI agents)
- **Default (pipe)**: Compact JSON for machine parsing
- **--json**: Compact JSON for machine parsing
- **--pretty**: Pretty-printed JSON (indented, multi-line)

Override with flags:
```bash
# Force JSON output (compact, single-line)
ghidra function list --json

# Force pretty JSON (indented, multi-line)
ghidra function list --pretty

# Select specific fields
ghidra function list --fields "name,address,size"
```

### Output Format Design

The bridge always emits compact JSON over the socket. The CLI decides the human-facing format at its own output boundary — human-readable when attached to a TTY, compact JSON when piped, or forced with `--json`/`--pretty`/`-o`. Doing it CLI-side keeps the wire protocol one stable shape with a single place that decides formatting.

## Filtering

Use expressions to filter results:

```bash
ghidra function list --filter "size > 100"
ghidra function list --filter "name ~ 'main'"
ghidra strings list --filter "length > 20"
```

## Environment Variables

Paths and defaults:

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Ghidra installation path |
| `GHIDRA_PROJECT_DIR` | Base directory for projects |
| `GHIDRA_CLI_JAVA_HOME` | Full JDK for Ghidra (overrides auto-detection) |
| `GHIDRA_CLI_CONFIG` | Override the config file path |
| `GHIDRA_DEFAULT_PROJECT` | Default `--project` for `ghidra query` |
| `GHIDRA_DEFAULT_PROGRAM` | Default `--program` for `ghidra query` and auto-selection |

Timeouts. Most default to unbounded so that a legitimately long analysis or
decompile isn't cut off. Set them when you'd rather fail fast:

| Variable | Purpose (default) |
|----------|-------------------|
| `GHIDRA_CLI_LAUNCH_TIMEOUT` | Cap on bridge launch readiness (180s) |
| `GHIDRA_CLI_OP_TIMEOUT` | Cap on long `analyze`/`import` ops (unbounded) |
| `GHIDRA_CLI_DECOMPILE_TIMEOUT` | Ghidra-side decompiler limit in seconds; `0` = unbounded (unbounded) |
| `GHIDRA_CLI_READ_TIMEOUT` | Per-request socket read timeout; `0` = indefinite (300s) |
| `GHIDRA_CLI_CONNECT_DEADLINE` | How long to retry connecting to a (re)starting bridge (60s) |
| `GHIDRA_CLI_SHUTDOWN_TIMEOUT` | Grace period to drain jobs before force-kill; `0` = indefinite (300s) |

## AI Agent Integration

Output is structured JSON and the command set is broad, so an agent can script a full reverse-engineering pass end to end. A representative workflow:
1. `ghidra import suspicious.exe --project analysis` - Import, auto-analyze, and start the bridge in one step
2. `ghidra find interesting` - AI analyzes suspicious patterns
3. `ghidra decompile <func>` - AI examines specific functions
4. `ghidra x-ref to <addr>` - AI traces data flow
5. `ghidra patch nop <addr>` - AI patches anti-debug code
6. `ghidra patch export -o patched.bin` - Export patched binary

## Troubleshooting

### Common Issues

#### Missing X11 Libraries (Linux/WSL)

If you see errors like `libXtst.so.6: cannot open shared object file`, install X11 libraries:

```bash
# Arch Linux / WSL with Arch
sudo pacman -S libxtst

# Ubuntu / Debian / WSL with Ubuntu
sudo apt install libxtst6

# Fedora / RHEL
sudo dnf install libXtst
```

#### Java Version Issues

Ghidra requires JDK 17 or higher (not just JRE):

```bash
# Arch Linux
sudo pacman -S jdk21-openjdk

# Ubuntu / Debian
sudo apt install openjdk-21-jdk

# Verify installation
java -version  # Should show 17+ and include "JDK"
```

#### WSL-Specific Notes

WSL requires X11 libraries even for headless operation because Java AWT is loaded during initialization:

1. Install X11 libraries (see above)
2. If using WSL1, consider upgrading to WSL2 for better compatibility
3. Bridge port/PID files are stored in `~/.local/share/ghidra-cli/`

#### Running Doctor

Use the doctor command to verify your installation:

```bash
ghidra doctor
```

This checks:
- Ghidra installation directory
- analyzeHeadless availability
- Project directory configuration
- Config file status

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

GPL-3.0 License - See [LICENSE](LICENSE) for details.

# Ghidra CLI

A high-performance Rust CLI for automating Ghidra reverse engineering tasks, designed for both direct usage and AI agent integration (like Claude Code).

## Features

- **Direct bridge architecture** - CLI connects directly to a Java bridge running inside Ghidra's JVM
- **Auto-start bridge** - Import/analyze commands automatically start the bridge
- **Fast queries** - Sub-second response times with Ghidra kept in memory
- **Comprehensive analysis** - Functions, symbols, types, strings, cross-references
- **Type system** - Create/edit structs, enums, typedefs; add/remove struct fields
- **Function signatures** - Edit return types, calling conventions, full C signatures; retype variables
- **Binary patching** - Modify bytes, NOP instructions, export patches
- **Call graphs** - Generate caller/callee graphs, export to DOT format
- **Search capabilities** - Find strings, bytes, functions, crypto patterns
- **Script execution** - Run Java/Python Ghidra scripts, inline or from files
- **Batch operations** - Execute multiple commands from a file
- **Flexible output** - Human-readable, JSON, or pretty JSON formats
- **Filtering** - Powerful expression-based filtering (e.g., `size > 100`)

## Architecture

```
┌─────────────────┐         ┌──────────────────────────────────────┐
│   CLI Command   │──TCP──▶ │  GhidraCliBridge.java                │
│   ghidra ...    │         │  (GhidraScript in analyzeHeadless)   │
│   --project X   │         │  ServerSocket on localhost:dynamic   │
└─────────────────┘         └──────────────────────────────────────┘
```

The CLI connects directly to a Java bridge running inside Ghidra's JVM. This provides:
- **Consistent state** - Single Ghidra process for all operations
- **Fast queries** - No JVM startup overhead per command
- **Auto-start** - Bridge starts automatically when needed
- **Per-project isolation** - Each project gets its own bridge process and port file, enabling concurrent analysis of multiple binaries
- **Minimal dependencies** - Only Ghidra + Java required (no Python/PyGhidra)

## Installation

### From Source

```bash
git clone https://github.com/akiselev/ghidra-cli
cd ghidra-cli
cargo install --path .
```

### Requirements

- **Ghidra 10.0+** - Download from [ghidra-sre.org](https://ghidra-sre.org)
- **Java 17+** - Required by Ghidra
- **Rust 1.70+** - For building from source

Set the Ghidra installation path:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Or configure via CLI:
ghidra config set ghidra_install_dir /path/to/ghidra
```

## Quick Start

```bash
# Check installation
ghidra doctor

# Import and analyze a binary (bridge auto-starts)
ghidra import ./binary --project myproject --program mybinary
ghidra analyze --project myproject --program mybinary

# Query functions (uses running bridge)
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

## Commands

### Project & Program Management
```bash
ghidra project create <name>           # Create project
ghidra project list                    # List projects
ghidra project delete <name>           # Delete project
ghidra import <binary> --project <p>   # Import binary (auto-starts bridge)
ghidra analyze --project <p>           # Run analysis
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

Note: `patch nop --count` is currently parsed by the CLI, but runtime uses single-address NOP behavior.

### Comments
```bash
ghidra comment get <address>           # Get comment
ghidra comment set <addr> "note" --comment-type EOL  # Set comment
ghidra comment list                    # List all comments
```

Note: `--comment-type` currently falls back to `EOL` due client/bridge argument key mismatch.

### Scripts
```bash
ghidra script list                     # List available scripts
ghidra script run myscript.py          # Run script file
ghidra script python "print(currentProgram)"  # Inline Python
```

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

Format detection occurs at the CLI boundary. The bridge always returns compact JSON for IPC efficiency. The CLI applies format transformation (human-readable, pretty JSON) at the output boundary based on TTY detection or explicit flags. This design maintains a stable IPC protocol with a single format decision point.

## Filtering

Use expressions to filter results:

```bash
ghidra function list --filter "size > 100"
ghidra function list --filter "name ~ 'main'"
ghidra strings list --filter "length > 20"
```

## AI Agent Integration

Ghidra CLI is designed to work seamlessly with AI coding assistants like Claude Code. The structured output and comprehensive command set make it ideal for automated reverse engineering workflows.

Example workflow with an AI agent:
1. `ghidra import suspicious.exe --project analysis` + `ghidra analyze --project analysis` - Import, analyze, start bridge
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

# Ghidra Binary Analysis Subagent

## Overview

This subagent specializes in reverse engineering binaries using Ghidra CLI. It provides efficient, token-optimized access to binary analysis capabilities for Claude Code and other AI agents.

## When to Use This Subagent

Use this subagent when you need to:
- Analyze binary executables (PE, ELF, Mach-O)
- Reverse engineer malware or suspicious binaries
- Extract functions, strings, imports/exports from binaries
- Decompile functions to understand behavior
- Find specific patterns in binary code
- Analyze memory layout and structure
- Identify crypto functions, network operations, or file I/O
- Generate reports on binary capabilities

## Capabilities

### Data Extraction
- **Functions**: List, filter, and decompile functions
- **Strings**: Extract and search string literals
- **Imports/Exports**: Analyze external dependencies
- **Memory Layout**: View memory regions and permissions
- **Symbols**: Access symbol table
- **Cross-References**: Find call relationships

### Analysis Features
- **Universal Query System**: Query any data type with powerful filters
- **Advanced Filtering**: Complex boolean expressions with field-level filtering
- **Multiple Output Formats**: JSON, CSV, Table, minimal (token-efficient)
- **Decompilation**: Convert assembly to C-like pseudocode
- **Pattern Matching**: Find specific code patterns and strings

### LLM Optimizations
- **Count-First Workflow**: Check result sizes before fetching data
- **Field Selection**: Request only needed fields
- **Aggressive Filtering**: Pre-filter on Ghidra side
- **Compact Formats**: Minimal token usage with `json-compact`
- **Pagination**: Handle large datasets efficiently

## Command Reference

### Quick Start

```bash
# Import and analyze a binary
ghidra import <binary-path> --project=<project>

# Get program summary
ghidra summary --program=<binary>
```

### Universal Query

```bash
# Query any data type
ghidra query <data-type> --program=<binary> [options]

# Data types: functions, strings, imports, exports, memory
# (symbols and xrefs have their own commands: `ghidra symbol list`, `ghidra x-ref ...`)

# Essential options:
  --filter="<expression>"    # Filter results
  --fields=<list>            # Select specific fields
  --format=<format>          # Output format (json, json-compact, table, count)
  --limit=<n>                # Max results
  --count                    # Just return count
```

### Common Queries

```bash
# List functions with filtering
ghidra query functions --program=<binary> \
  --filter="size>1000 AND name~crypt" \
  --fields=name,address,size \
  --format=json-compact

# Find strings
ghidra query strings --program=<binary> \
  --filter="value~http" \
  --format=minimal

# List imports
ghidra dump imports --program=<binary> \
  --filter="name~Crypt" \
  --format=json-compact

# Get memory map
ghidra query memory --program=<binary> --format=table
```

### Decompilation

```bash
# Decompile function by address
ghidra decompile 0x401000 --program=<binary>

# Decompile by name
ghidra decompile main --program=<binary>

# Compact output
ghidra fn decompile <addr> --program=<binary> --format=compact
```

## Filter Language

### Operators

```
Comparison:     =, !=, >, >=, <, <=
String:         ~ (contains), ^ (starts), $ (ends), =~ (regex)
Logical:        AND, OR, NOT, ()
Special:        EXISTS, IN [val1,val2]
```

### Examples

```bash
# Exact match
name=malloc

# Numeric comparison
size>1000

# String matching (case-insensitive)
name~crypt

# Boolean logic
name~crypt AND size>500
(name~main OR name~start) AND NOT name^FUN_

# IN operator
name IN [malloc,free,realloc]

# Field existence
calls EXISTS

# Complex expression
size>=100 AND size<=1000 AND (name~crypt OR calls~Crypt)
```

## Output Formats

- `count` - Just the number (check result size)
- `json-compact` - Minimal JSON (best for LLMs)
- `minimal` - Addresses/names only (piping)
- `ids` - Just IDs (for further queries)
- `table` - Human-readable (display)
- `json` - Full JSON (complete data)

## Best Practices

### 1. Count-First Pattern

Always check the result size before fetching data:

```bash
# Step 1: Count
ghidra query functions --program=<binary> --count

# Step 2: Refine filter if needed
ghidra query functions --program=<binary> \
  --filter="NOT name^FUN_" \
  --count

# Step 3: Fetch minimal data
ghidra query functions --program=<binary> \
  --filter="NOT name^FUN_" \
  --fields=name,address \
  --format=json-compact \
  --limit=50
```

### 2. Aggressive Filtering

Filter on Ghidra side, not in your code:

```bash
# GOOD: Pre-filter
ghidra query functions --program=<binary> \
  --filter="size>1000 AND name~crypt"

# BAD: Fetch all, then filter
ghidra query functions --program=<binary>  # Then filter in code
```

### 3. Field Selection

Request only what you need:

```bash
# Only name and address
ghidra query functions --program=<binary> \
  --fields=name,address \
  --format=json-compact
```

### 4. Use Compact Formats

Minimize token usage:

```bash
# For analysis: json-compact
--format=json-compact

# For display: table
--format=table

# For piping: minimal or ids
--format=ids
```

## Analysis Workflows

### Initial Reconnaissance

```bash
# 1. Get summary
ghidra summary --program=<binary>

# 2. Count functions
ghidra query functions --program=<binary> --count

# 3. Count named functions
ghidra query functions --program=<binary> \
  --filter="NOT name^FUN_" --count

# 4. List key functions
ghidra query functions --program=<binary> \
  --filter="NOT name^FUN_" \
  --fields=name,address,size \
  --format=json-compact \
  --limit=20
```

### Finding Suspicious Behavior

```bash
# Network operations
ghidra query imports --program=<binary> \
  --filter="name~socket OR name~http OR name~inet" \
  --format=json-compact

# File operations
ghidra query imports --program=<binary> \
  --filter="name~File OR name~Read OR name~Write" \
  --format=json-compact

# Process operations
ghidra query imports --program=<binary> \
  --filter="name~Process OR name~Thread OR name~Exec" \
  --format=json-compact

# Crypto operations
ghidra query imports --program=<binary> \
  --filter="name~Crypt" \
  --format=json-compact
```

### String Analysis

```bash
# URLs
ghidra query strings --program=<binary> \
  --filter="value~http" \
  --format=json-compact

# Registry keys
ghidra query strings --program=<binary> \
  --filter="value~HKEY OR value~Software" \
  --format=json-compact

# Credentials
ghidra query strings --program=<binary> \
  --filter="value~password OR value~username OR value~key" \
  --format=json-compact

# Long strings (paths, URLs)
ghidra query strings --program=<binary> \
  --filter="length>50" \
  --format=json-compact
```

### Deep Dive Analysis

```bash
# 1. Find interesting functions
ghidra query functions --program=<binary> \
  --filter="name~crypt OR calls~Crypt" \
  --fields=name,address \
  --format=json-compact

# 2. Decompile each
ghidra decompile <address> --program=<binary>

# 3. Find cross-references
ghidra xref to <address> --program=<binary> \
  --format=json-compact

# 4. Analyze callers
ghidra fn calls <address> --program=<binary> \
  --format=json-compact
```

## Common Patterns

### Pattern: Find Entry Point

```bash
ghidra query functions --program=<binary> \
  --filter="name~main OR name~WinMain OR name~DllMain" \
  --format=json-compact
```

### Pattern: Find Crypto Functions

```bash
# By name
ghidra query functions --program=<binary> \
  --filter="name~crypt OR name~cipher OR name~aes OR name~rsa" \
  --format=json-compact

# By imports
ghidra query imports --program=<binary> \
  --filter="name~Crypt" \
  --format=json-compact
```

### Pattern: Find Large/Complex Functions

```bash
ghidra query functions --program=<binary> \
  --filter="size>2000" \
  --fields=name,address,size \
  --sort=-size \
  --limit=10 \
  --format=json-compact
```

### Pattern: Trace Function Calls

```bash
# What does function call?
ghidra fn calls <function> --program=<binary> \
  --format=json-compact

# What calls this function?
ghidra fn xrefs <function> --program=<binary> \
  --format=json-compact
```

## Configuration

### Set Defaults (avoid repeating --program)

```bash
# Set default program
ghidra set-default program <binary>

# Now you can omit --program
ghidra query functions --count
```

### Environment Variables

```bash
# Windows
set GHIDRA_INSTALL_DIR=C:\ghidra\ghidra_11.0
set GHIDRA_DEFAULT_PROGRAM=malware.exe

# Unix
export GHIDRA_INSTALL_DIR=/opt/ghidra
export GHIDRA_DEFAULT_PROGRAM=malware.elf
```

## Error Handling

### Common Issues

1. **Ghidra not found**: Run `ghidra doctor` to check installation, or set `GHIDRA_INSTALL_DIR`
2. **Program not specified**: Use `--program=<binary>` or set default
3. **Large result set**: Use `--count` first, then filter more aggressively

### Troubleshooting

```bash
# Check installation
ghidra doctor

# Show configuration
ghidra config list

# List projects
ghidra project list
```

## Performance Considerations

1. **Always count first** - Prevents context overflow
2. **Filter aggressively** - Reduce data before transfer
3. **Select minimal fields** - Less data = fewer tokens
4. **Use compact formats** - `json-compact` is most efficient
5. **Paginate results** - Use `--limit` for large datasets
6. **Cache results** - Store commonly-used data in variables

## Example: Complete Analysis

```bash
# Import binary
ghidra import suspicious.exe --project=analysis

# Set as default
ghidra set-default program suspicious.exe

# Overview
ghidra summary

# Count functions
ghidra query functions --count
# → 1247

# Named functions only
ghidra query functions --filter="NOT name^FUN_" --count
# → 89

# Get named functions
ghidra query functions \
  --filter="NOT name^FUN_" \
  --fields=name,address,size \
  --format=json-compact

# Find suspicious imports
ghidra dump imports \
  --filter="name~Exec OR name~Process OR name~Write" \
  --format=json-compact

# Find URLs/IPs
ghidra query strings \
  --filter="value~http OR value=~\"[0-9]{1,3}\\.[0-9]{1,3}\"" \
  --format=json-compact

# Decompile interesting functions
ghidra decompile 0x401000

# Find what calls it
ghidra xref to 0x401000 --format=json-compact
```

## Integration Tips

This subagent works best when:
- You have a binary file that needs analysis
- You need to understand malware behavior
- You're investigating suspicious executables
- You need to extract specific information (strings, functions, imports)
- You want to generate a report on binary capabilities

The subagent is optimized for:
- Token efficiency (minimal output)
- Fast queries (count-first pattern)
- Precise filtering (server-side pre-filtering)
- Flexible output (multiple formats)
- Automation-friendly (scriptable)

## Limitations

- Requires Ghidra to be installed
- Windows path handling is primary (but cross-platform)
- Initial analysis can be slow for large binaries
- Decompilation quality depends on Ghidra's capabilities
- Complex analysis may require multiple queries

## Support

- Run `ghidra doctor` to check installation
- See `README.md` for full documentation

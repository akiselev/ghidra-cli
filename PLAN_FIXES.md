# Fix Plan: ghidra-cli Code Review Issues

## Phase 1: Quick Wins (Independent, Parallelizable)

### Task 1: Fix `--quiet` flag (High Priority)
**Files:** `src/main.rs`
**Problem:** `cli.quiet` is defined but never checked. All eprintln! status messages still appear.
**Fix:** Thread `cli.quiet` through to suppress eprintln! messages in:
- `run_with_bridge()`: "Starting Ghidra bridge...", "Bridge ready."
- `handle_bridge_start()`: status messages
- `handle_bridge_stop()`: status messages
- Import path: "Successfully imported as: ..."
- Analyze path: "Analyzing...", "Analysis complete!"
Approach: pass `quiet: bool` to the relevant functions, or check it before each eprintln!.

### Task 2: Fix `--sort` hyphen ambiguity (High Priority)
**Files:** `src/cli.rs`
**Problem:** `--sort -size` is parsed as `--sort` + `-s ize` by clap. Users must use `--sort=-size`.
**Fix:** Add `allow_hyphen_values = true` to the `sort` field in `QueryOptions`:
```rust
#[arg(long, allow_hyphen_values = true)]
pub sort: Option<String>,
```

### Task 3: Replace deprecated `atty` with `std::io::IsTerminal` (Low Priority)
**Files:** `src/main.rs`, `Cargo.toml`
**Problem:** `atty` 0.2 is deprecated. `std::io::IsTerminal` is stable since Rust 1.70.
**Fix:**
- Replace `atty::is(atty::Stream::Stdout)` with `std::io::stdout().is_terminal()`
- Remove `atty` from `Cargo.toml` dependencies

### Task 4: Fix `default_limit` config being unused (Medium Priority)
**Files:** `src/main.rs`
**Problem:** `Config.default_limit` exists but `list_functions()`, `list_strings()` etc. never use it.
**Fix:** In `execute_via_bridge()`, for commands that take a limit from `QueryOptions`, fall back to `config.default_limit` when the user doesn't specify one. The simplest approach: thread the config into `execute_via_bridge` and apply the default at the QueryOptions extraction point. Since `execute_via_bridge` doesn't currently receive config, the cleanest fix is to resolve the limit before calling it - apply `config.default_limit` to the QueryOptions limit if it's None.

### Task 5: Fix per-command `--json` in QueryOptions being ignored (Medium Priority)
**Files:** `src/main.rs`
**Problem:** `QueryOptions.json` exists but format detection only checks `cli.json` (global).
**Fix:** In `run_with_bridge()`, after extracting `opts`, also check `opts.json`:
```rust
} else if cli.json || opts.as_ref().map_or(false, |o| o.json) {
    OutputFormat::JsonCompact
}
```

## Phase 2: Structural Refactoring

### Task 6: Remove dead `daemon/` module (Low Priority)
**Files:** `src/daemon/mod.rs`, `src/daemon/README.md`, `src/main.rs`
**Problem:** Entire module is `#[allow(dead_code)]` with no callers.
**Fix:**
- Delete `src/daemon/mod.rs` and `src/daemon/README.md`
- Remove `mod daemon;` from `src/main.rs`
- Update CLAUDE.md to remove daemon references

### Task 7: Deduplicate `headless_script` lookup (Low Priority)
**Files:** `src/ghidra/mod.rs`, `src/ghidra/bridge.rs`
**Problem:** `GhidraClient::get_headless_script()` and `bridge::find_headless_script()` duplicate the same logic.
**Fix:** Make `bridge::find_headless_script()` the canonical implementation. Have `GhidraClient::get_headless_script()` call it:
```rust
pub fn get_headless_script(&self) -> Result<PathBuf> {
    bridge::find_headless_script(&self.install_dir)
}
```
Note: return type changes from `PathBuf` to `Result<PathBuf>` - update callers.

### Task 8: Fix `stop_bridge` SIGTERM race (Low Priority)
**Files:** `src/ghidra/bridge.rs`
**Problem:** After sending graceful shutdown via TCP, immediately kills with SIGTERM without waiting.
**Fix:** Add a brief wait + check loop after the TCP shutdown before falling back to kill:
```rust
// Wait up to 3 seconds for graceful shutdown
if let Ok(Some(pid)) = read_pid_file(project_path) {
    for _ in 0..30 {
        if !is_pid_alive(pid) {
            cleanup_stale_files(project_path)?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Still alive - force kill
    warn!("Killing bridge process {} as fallback", pid);
    ...
}
```

### Task 9: Fix `config set` to support all keys (Medium Priority)
**Files:** `src/main.rs`
**Problem:** `config set` only handles `default_output_format` and `timeout`. Other valid config keys error.
**Fix:** Extend the match in `handle_config_command` to support all config keys:
- `ghidra_install_dir` -> set as PathBuf
- `ghidra_project_dir` -> set as PathBuf
- `default_program` -> set as String
- `default_project` -> set as String
- `default_limit` -> parse as usize

### Task 10: Extract `extract_*` boilerplate via trait (Medium Priority - Optional)
**Files:** `src/cli.rs`, `src/main.rs`
**Problem:** Three ~100-line functions exhaustively match every command variant to extract project/program/query options.
**Fix:** Add a trait to cli types:
```rust
pub trait HasQueryOptions {
    fn query_options(&self) -> Option<&QueryOptions>;
    fn project(&self) -> Option<&String>;
    fn program(&self) -> Option<&String>;
}
```
Implement on each command struct, then the extract functions become one-liners. This is a larger refactor - can be done as a follow-up.

## Phase 3: Cleanup

### Task 11: Clean up dead code warnings
**Files:** `src/error.rs`, various test files
**Problem:** Unused error variants, deprecated test APIs, unused imports in test modules.
**Fix:**
- Remove `#![allow(dead_code)]` from error.rs and remove unused variants
- Or keep them if they're part of the planned API surface (add targeted allows)
- Clean up test file imports

## Execution Order

Tasks 1-5 are independent and can be done in parallel.
Tasks 6-9 are independent and can be done in parallel.
Task 10 is optional and depends on comfort with the refactor scope.
Task 11 is cleanup and should go last.

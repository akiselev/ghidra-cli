# E2E Test Suite

Comprehensive end-to-end test coverage for ghidra-cli commands.

## Architecture

Tests are organized by functional area into separate files:

```
tests/
├── common/
│   ├── mod.rs           # DaemonTestHarness, fixtures, helpers
│   ├── helpers.rs       # GhidraCommand builder, GhidraResult assertions
│   └── schemas.rs       # Response validation schemas
├── daemon_tests.rs      # Bridge lifecycle: start/stop/restart/status/ping
├── project_tests.rs     # Project: create/list/delete/info
├── reliability_tests.rs # Bridge restart recovery, stale file cleanup
├── command_tests.rs     # Basic commands: version/doctor/config/init
├── comment_tests.rs     # Comment operations
├── patch_tests.rs       # Binary patching operations
├── readonly_tests.rs    # Read-only query tests
├── script_tests.rs      # Script execution
├── symbol_tests.rs      # Symbol operations
├── tag_tests.rs         # Function tag operations
├── type_tests.rs        # Type operations
├── output_format_integration.rs  # Output format detection
└── e2e.rs               # Lightweight smoke test
```

## Per-Suite Bridge Lifecycle

Tests requiring bridge interaction use `DaemonTestHarness` from `common/mod.rs`. Each test suite starts its own bridge instance to amortize 5-30s startup overhead across all tests in that file.

**Why per-suite instead of per-test**: Starting a bridge for every test would add 5-30 minutes to CI time for 60+ tests. Per-suite bridges run tests serially within the suite but allow parallel execution across different test files.

**Why not shared global bridge**: State leakage between suites causes flaky tests and debugging nightmares. Each suite gets isolation.

## Data Flow

```
Test Suite Start
      |
      v
DaemonTestHarness::new()
      |
      +---> Start bridge (analyzeHeadless + GhidraCliBridge.java)
      +---> Wait for port file
      +---> Verify with ping
      |
      v
Run tests (serial within suite)
      |
      v
DaemonTestHarness::drop()
      |
      +---> Send shutdown command via TCP
      +---> Cleanup port/PID files
```

## Running Tests

Run all tests:
```bash
cargo test
```

Run specific test suite:
```bash
cargo test --test daemon_tests
cargo test --test command_tests
```

Run single test:
```bash
cargo test --test command_tests test_version
```

Run tests that don't need Ghidra:
```bash
cargo test --test e2e --test output_format_integration
```

## Test Requirements

### Ghidra Installation

Tests assume Ghidra is installed. Use `require_ghidra!()` in tests that need a fast, explicit availability check; it panics (fails the test) if `ghidra doctor` fails.

### Test Fixtures

Sample binary fixture required: `tests/fixtures/sample_binary`

Build fixture:
```bash
rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
```

Fixture contains functions: add, multiply, factorial, fibonacci, process_string, xor_encrypt, simple_hash, init_data, main

## Adding New Tests

### Non-Bridge Tests

Add to appropriate file (`command_tests.rs`, `project_tests.rs`):

```rust
#[test]
fn test_my_command() {
    require_ghidra!();

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("my-command")
        .assert()
        .success();
}
```

### Bridge-Dependent Tests

Add to the appropriate test file (e.g., `symbol_tests.rs`, `readonly_tests.rs`):

```rust
#[test]
#[serial]
fn test_my_query() {
    require_ghidra!();

    ensure_test_project(TEST_PROJECT, TEST_PROGRAM);

    let harness =
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start bridge");

    Command::cargo_bin("ghidra")
        .unwrap()
        .arg("--project")
        .arg(TEST_PROJECT)
        .arg("my-query")
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success();

    drop(harness);
}
```

Mark with `#[serial]` to prevent bridge state races within suite.

## Invariants

- Bridge must be fully started before any query test runs
- Each test suite gets its own bridge instance (no sharing)
- Port/PID files must be cleaned up even on test failure (Drop impl)
- Tests must not assume specific function addresses (use name-based lookups)

## Troubleshooting

### "Bridge failed to start within timeout"

Ghidra cold start can be slow. Ensure:
- Ghidra installation is valid (`ghidra doctor`)
- Sufficient disk space for temporary Ghidra project
- Not running on extremely constrained CI resources

### "Test fixture not found"

Compile sample_binary:
```bash
rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
```

### "Port already in use" / stale port files

Each test suite uses project-name-based port file paths to prevent collisions. This error suggests:
- Previous test run leaked bridge process (kill manually)
- Stale port/PID files in `~/.local/share/ghidra-cli/`

Find leaked processes:
```bash
ps aux | grep ghidra
kill <pid>
```

### Tests hang or timeout

- Check if bridge is stuck (check process list)
- Verify TCP connectivity on localhost
- Increase timeout in test (bridge startup can vary)

### Import/analysis takes too long

Tests use 300s timeout for import/analyze operations. On slow systems:
- Run fewer parallel test suites
- Ensure Ghidra has adequate heap memory
- Check disk I/O performance

## Tradeoffs

**Per-suite vs per-test bridge**: Chose speed over maximum isolation. Tests within suite are serial, but suite-to-suite parallelism maintained.

**Project-name-based port files vs random ports**: Each test suite uses a unique project name which maps to a unique port file via MD5 hash, preventing collisions.

**Testing unimplemented commands**: Adds maintenance burden but documents gaps and ensures graceful failures for stub commands.

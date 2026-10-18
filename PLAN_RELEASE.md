# Show HN Release Preparation Plan

## Overview

Prepare ghidra-cli for open source release and Show HN announcement. The project has solid core functionality but needs standard OSS documentation and CI/CD infrastructure. User confirmed: Option B (Standard OSS) with GPL-3.0 license.

Key deliverables:
1. Fix license mismatch (README says MIT, should say GPL-3.0)
2. Create CONTRIBUTING.md with development setup
3. Create CI/CD workflows (test, lint, release)
4. Create CHANGELOG.md

## Planning Context

### Decision Log

| Decision | Reasoning Chain |
|----------|-----------------|
| GPL-3.0 license | User-specified → LICENSE file already contains GPL-3.0 text → Cargo.toml already specifies GPL-3.0 → only README needs update |
| Standard OSS approach over minimal | User-specified → professional appearance matters for HN → community contributions need clear guidelines → CI/CD prevents regressions |
| Separate CI workflows over single workflow | Each workflow has different triggers → test on PR, lint on PR, release on tag → separation allows independent failure/success |
| CONTRIBUTING.md includes Ghidra requirement | AGENTS.md specifies "NEVER SKIP TESTS" → tests require Ghidra installation → contributors must know this upfront |
| GitHub Actions over alternatives | Industry standard → already have claude.yml workflow → consistent with ecosystem expectations |

### Rejected Alternatives

| Alternative | Why Rejected |
|-------------|--------------|
| MIT license | User explicitly chose GPL-3.0; LICENSE file already contains GPL-3.0 |
| Minimal release (Option A) | User chose Standard OSS for professional HN appearance |
| Single monolithic CI workflow | Harder to debug failures; different triggers needed for test vs release |
| Pre-built binaries in first release | Can add later; initial release focuses on source distribution |

### Constraints & Assumptions

- **License**: GPL-3.0 (user-specified)
- **Existing patterns**: Project already has claude.yml workflow in .github/workflows/
- **Test requirement**: AGENTS.md mandates "NEVER SKIP TESTS! IF GHIDRA IS NOT INSTALLED, THE TESTS MUST FAIL"
- **Output format**: AGENTS.md mandates human-readable default output

### Known Risks

| Risk | Mitigation | Anchor |
|------|------------|--------|
| CI tests fail without Ghidra | Document that full test suite requires Ghidra; basic cargo build/clippy can run without | AGENTS.md:5 |
| Contributors confused by daemon architecture | CONTRIBUTING.md explains daemon-only pattern | AGENTS.md:10-14 |

## Invisible Knowledge

### CI/CD Architecture

```
Push/PR to main
       |
       v
+----------------+
| test.yml       | --> cargo test --lib (unit tests)
| (on: push/PR)  | --> cargo build
+----------------+
       |
       v
+----------------+
| lint.yml       | --> cargo fmt --check
| (on: push/PR)  | --> cargo clippy
+----------------+

Tag (v*)
       |
       v
+----------------+
| release.yml    | --> cargo publish (crates.io)
| (on: tag)      | --> GitHub release
+----------------+
```

### Why This Structure

- **Separate workflows**: Each can fail independently; easier debugging
- **No Ghidra in CI**: Full integration tests require local Ghidra installation; CI runs unit tests and build verification only
- **Release on tag**: Manual control over when to publish; prevents accidental releases

### Invariants

- All workflows must pass before merging PRs
- Release workflow only triggers on version tags (v*)
- CONTRIBUTING.md must stay synchronized with AGENTS.md requirements

## Milestones

### Milestone 1: Fix License Documentation

**Files**:
- `README.md`

**Requirements**:
- Update license section to correctly state GPL-3.0
- Remove incorrect MIT claim

**Acceptance Criteria**:
- README.md mentions GPL-3.0 license
- No mention of MIT license remains
- LICENSE file unchanged (already correct)

**Tests**: Skip - documentation only

**Code Intent**:
- Find the license section in README.md (currently says "MIT License")
- Change to "GPL-3.0 License - See [LICENSE](LICENSE) for details"

---

### Milestone 2: Create CONTRIBUTING.md

**Files**:
- `CONTRIBUTING.md` (new)

**Requirements**:
- Development setup instructions
- Test requirements (Ghidra mandatory per AGENTS.md)
- Code style guidelines
- PR submission process
- Daemon architecture overview

**Acceptance Criteria**:
- File exists at repository root
- Contains sections: Getting Started, Development Setup, Testing, Code Style, Pull Requests
- References AGENTS.md for architecture details
- Clearly states Ghidra is required for full test suite

**Tests**: Skip - documentation only

**Code Intent**:
- Create new file with standard OSS contributing guide structure
- Include: Prerequisites (Rust 1.70+, Ghidra 10.0+, Java 17+)
- Include: Build instructions (cargo build, cargo test)
- Include: Test requirement from AGENTS.md ("NEVER SKIP TESTS")
- Include: Output format convention from AGENTS.md
- Include: Brief daemon architecture explanation
- Include: PR process and code review expectations

---

### Milestone 3: Create CI/CD Workflows

**Files**:
- `.github/workflows/test.yml` (new)
- `.github/workflows/lint.yml` (new)
- `.github/workflows/release.yml` (new)

**Requirements**:
- test.yml: Run cargo test and cargo build on push/PR
- lint.yml: Run cargo fmt --check and cargo clippy on push/PR
- release.yml: Publish to crates.io on version tag

**Acceptance Criteria**:
- All three workflow files exist
- test.yml triggers on push to main and PRs
- lint.yml triggers on push to main and PRs
- release.yml triggers only on tags matching v*
- Workflows use latest stable Rust

**Tests**: Skip - CI configuration files

**Code Intent**:
- Create test.yml:
  - Trigger: push to main, pull_request
  - Jobs: cargo build, cargo test --lib
  - Matrix: ubuntu-latest (can expand to macos/windows later)

- Create lint.yml:
  - Trigger: push to main, pull_request
  - Jobs: cargo fmt --check, cargo clippy -- -D warnings

- Create release.yml:
  - Trigger: tags matching v*
  - Jobs: cargo publish
  - Requires: CARGO_REGISTRY_TOKEN secret

---

### Milestone 4: Create CHANGELOG.md

**Files**:
- `CHANGELOG.md` (new)

**Requirements**:
- Follow Keep a Changelog format
- Document initial release (v0.1.0)
- Include main features

**Acceptance Criteria**:
- File exists at repository root
- Contains [Unreleased] section
- Contains [0.1.0] section with initial features
- Links to GitHub compare URLs

**Tests**: Skip - documentation only

**Code Intent**:
- Create new file following Keep a Changelog format
- Add header with format description
- Add [Unreleased] section (empty)
- Add [0.1.0] section with:
  - Added: Daemon-only architecture, 30+ commands, output format options, AI agent integration

---

### Milestone 5: Documentation Update

**Delegated to**: @agent-technical-writer (mode: post-implementation)

**Source**: `## Invisible Knowledge` section of this plan

**Files**:
- `CLAUDE.md` (update if needed)

**Requirements**:
- Ensure CLAUDE.md references new files (CONTRIBUTING.md, CHANGELOG.md)
- Verify navigation index is current

**Acceptance Criteria**:
- CLAUDE.md is tabular index only
- References to new documentation files included

## Milestone Dependencies

```
M1 (License) ----+
                 |
M2 (CONTRIBUTING)+--> M5 (Doc Update)
                 |
M3 (CI/CD) ------+
                 |
M4 (CHANGELOG) --+
```

- M1, M2, M3, M4 can execute in parallel (Wave 1)
- M5 depends on all others (Wave 2)

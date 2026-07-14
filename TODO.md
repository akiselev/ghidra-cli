# ghidra-cli TODO

Issues found while using ghidra-cli 0.2.0 on the parasolid-re project
(`pskernel.dll`, 45,246 functions).

## Bug 1 — `--limit 0` returns 0 rows instead of "all rows" — FIXED

`--limit 0` now means "all rows" in both the client-side paginator
(`src/query/mod.rs` `apply_pagination`) and the bridge request
(`src/main.rs` `bridge_list_params`), matching the bridge's own `limit > 0`
convention. It no longer falls back to the 1000-row default; omitting
`--limit` still applies `default_limit`. Unit tests cover both sites.

Verified against parasolid-re: `dump exports --limit 0` → 2909,
`function list --limit 0` → 44999, `symbol list --limit 0` → 1,902,150,
`dump strings --limit 0` → 48256.

This also resolves the "no clean everything flag" note: `--limit 0` is now
the ergonomic "give me all rows" option.

## Bug 2 — malformed `--filter` silently dumps the ENTIRE dataset — FIXED

Two layers:

1. `run_with_bridge` (`src/main.rs`) validates `--filter` up front and exits
   nonzero with a usage hint *before* any bridge fetch (a filtered query pulls
   the full dataset, so failing late wasted that transfer).
2. The output path no longer swallows `Query::from_options` errors
   (`if let Ok(Some(...))` → propagated with `describe_query_error`), so a
   parse failure can never fall through to the dump-everything formatter.

The filter DSL is now summarized in `--help` for `--filter`, and `--limit`
documents `0 = unlimited`. Bare words remain rejected (no implicit
`name~<word>` shorthand — the error message suggests it instead).

Verified: `symbol list --filter PK --limit 20` → exit 1 with a 185-byte error
message (previously a ~184 MB dump with exit 0).

## Bug 3 (found while verifying Bug 2) — `=~` regex was case-sensitively matched against lowercased fields — FIXED

`evaluate_string_op` lowercases field values, but compiled the regex
case-sensitively, so the documented `--filter 'name=~"^PK_"'` matched
nothing, silently. Regexes are now compiled case-insensitive (consistent with
`~`/`^`/`$`) and cached per pattern instead of recompiled per row — a filtered
count over the 1.9M-symbol table dropped from >10 min to ~55 s.

Verified: `symbol list --filter 'name=~"^PK_"' --count` → 1204.

## Bug 4 (found while running the suite) — test infra deleted the ci-test project from under a leaked bridge — FIXED

`ensure_test_project` (tests/common/mod.rs) required a non-empty `.gpr` to
accept the cached project, but Ghidra 12.1 headless close routinely leaves
`.gpr` at 0 bytes (healthy projects, including parasolid's, all have 0-byte
`.gpr`). So every run invalidated the cache and deleted `.gpr`/`.rep` — while a
bridge from the previous test binary was often still running, because the
`static OnceLock<DaemonTestHarness>` is never dropped. The re-import then went
over TCP into that bridge's now-file-less in-memory project, persisted nothing
on stop, and the next `-process` launch failed with "Could not find project",
failing every test in the binary (e.g. all 49 readonly_tests).

Fixed by (a) dropping the `.gpr` non-empty requirement — upstream had already
fixed this independently in v0.2.0 (d458648, with a stronger idata
subdirectory check that also covers a Windows `~index.bak` false-positive);
after rebasing, upstream's check is kept — and (b) stopping any running
ci-test bridge before deleting stale project files (kept on top of upstream;
they did not have this part). Side effect: suites now actually reuse the
cached project — filter tests dropped from ~330 s to ~12 s.

Also: `test_function_list_filter` used a bare-word `--filter main` and only
passed because of Bug 2 (the unfiltered full dump contained `main`). It now
uses `name~main` and asserts ALL rows match; a new
`test_function_list_bare_word_filter_rejected` asserts bare words exit nonzero.

## Reconciliation notes (2026-07-14 rebase onto v0.2.0)

- The uncommitted `src/ghidra/bridge.rs` change (stop grace 3 s → 120 s) was
  dropped: it was an abandoned draft of the "saves not working" fix that
  upstream solved better in e4ad023/d458648 with `import_oneshot` — a one-shot
  blocking import that durably commits before the persistent bridge starts,
  removing the fragile persist-during-teardown path entirely.
- The `local-work-pre-sync-2026-06-18` stash predates the M3+ restructure
  (still contains ilspy-cli/, crackme/, old test layout) and is almost
  certainly obsolete — review and drop it.

## Follow-ups (not yet done)

- `test_import_binary` (tests/project_tests.rs) has a 300 s timeout but a full
  import-with-analysis takes ~220 s even on an idle machine now that `import`
  analyzes by default — under load it times out (seen 2026-07-14 while another
  agent ran an 8 G Ghidra analysis concurrently). Consider raising to 600 s to
  match the analyze step's budget in `ensure_test_project`.

- The filter grammar (`src/filter.pest`) doesn't anchor `expr` with `SOI`/`EOI`,
  so trailing garbage after a valid expression (e.g. `name=test garbage`) may be
  silently ignored rather than rejected.
- `docs/GHIDRA_WORKFLOW.md` in parasolid-re documented `--limit 0` as
  "unlimited" before it was true; that is now accurate and the
  `--limit 1000000` workaround there can be dropped.

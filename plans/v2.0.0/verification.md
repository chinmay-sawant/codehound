# Verification

This document describes the verification procedure for each phase of
the file-split plan. Every phase should be verified end-to-end before
moving to the next one.

## Master verification

After **all** phases are complete:

```bash
# Build every feature combination
cargo build
cargo build --features go
cargo build --features python
cargo build --features go,python

# Run the full test suite
cargo test --features go,python
cargo test --all-features

# Run the bench compilation check (Criterion)
cargo bench --no-run

# Lint and format
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings

# Verify the generated code is byte-stable
cargo clean
cargo build --features go,python
git diff --stat target/   # Should be empty (generated files are in OUT_DIR and excluded from VCS)
```

## Per-phase verification

### Phase 1 (Engine / AST / Core / CWE / taint)

```bash
# After every batch:
cargo build --features go
cargo test --lib --features go

# Final, after all engine + cwe + taint splits:
cargo build --features go
cargo test --test cwe_catalog --test lang_go_detectors_cwe_facts \
           --test lang_go_detectors_cwe_common --test lang_go_cwe_metadata \
           --test engine_cache --test engine_baseline --test engine_config \
           --test engine_ignore --test engine_observability --test engine_result \
           --test engine_sinks --test engine_source_cache --test engine_language_filter

# Confirm public API is byte-identical via rustdoc JSON
cargo rustdoc --lib --features go -- -Zunstable-options --output-format json
```

The wildcard import in
`tests/lang_go_detectors_cwe_facts.rs:10`
(`use slopguard::lang::go::detectors::cwe::facts::*;`) is the canary
for `facts.rs` re-exports.

### Phase 2 (Top-level src)

```bash
# After every batch:
cargo build
cargo test --test app_baseline --test app_inline_ignore \
           --test reporting_text --test reporting_json --test reporting_sarif \
           --test export --test cli_baseline
```

### Phase 3 (CWE detectors)

```bash
# After every batch:
cargo build --features go
cargo test --test go_cwe_detector_integration

# Final, after all CWE detector splits:
cargo test --test go_cwe_detector_integration --test lang_go_cwe_metadata \
           --test lang_go_detectors_cwe_common --test lang_go_detectors_cwe_facts

# Cross-check that BP_*_META references still work
cargo test --test go_perf_detector_integration
```

**Canary test:** `tests/go_cwe_detector_integration.rs` discovers
fixtures by CWE id, runs every CWE-N detector, and asserts the
registry has not drifted. If a `pub use` is forgotten, this test
will report a missing finding for the affected CWE.

### Phase 4 (PERF detectors)

```bash
# After every batch:
cargo build --features go
cargo test --test go_perf_detector_integration --test go_perf_registry_generation

# Final, after all PERF splits:
cargo test --test go_perf_detector_integration --test go_perf_registry_generation \
           --test go_perf_ruleset_audit
```

### Phase 5 (Config & build)

```bash
# After every batch:
cargo build --features go,python
cargo test --test go_perf_registry_generation --test engine_config --test engine_baseline

# Final, after all config & build splits:
cargo clean
cargo build --features go,python
```

**Confirm** the generated `OUT_DIR/*.rs` files are byte-identical
across the change:
```bash
cargo build --features go,python
# Save the current output
cp -r target/debug/build/slopguard-*/out out_after
# Reset and rebuild
cargo clean
git stash
cargo build --features go,python
cp -r target/debug/build/slopguard-*/out out_before
git stash pop
diff -r out_before out_after    # Should be empty
```

### Phase 6 (Tests & benches)

```bash
# After every batch:
cargo test --test <name> --features go,python

# Final, after all test splits:
cargo test --features go,python
cargo test --all-features

# Bench compilation only (Criterion benches are not run automatically)
cargo bench --no-run
```

## Per-batch verification protocol

For every batch (a single file split or a small group of related
splits):

1. **Build all features**:
   ```bash
   cargo build --features go,python
   ```
2. **Run the tests that touch the split file(s)**:
   ```bash
   cargo test --test <affected_tests> --features go,python
   ```
3. **Run the linter**:
   ```bash
   cargo clippy --all-features --all-targets -- -D warnings
   cargo fmt --check
   ```
4. **Diff the generated code** (Phase 3 / 4 / 5 only):
   ```bash
   # Save the previous generated output
   cp -r target/debug/build/slopguard-*/out /tmp/slopguard_out_before
   # Rebuild
   cargo clean
   cargo build --features go,python
   # Compare
   diff -r /tmp/slopguard_out_before target/debug/build/slopguard-*/out
   ```
5. **Commit** the batch (small commits, one per file or per logical
   group).

## Regression tests

The following tests are the canaries for the entire plan:

| Test | What it catches |
|---|---|
| `tests/go_cwe_detector_integration.rs` | every `pub use` re-export in CWE detector splits (Phase 3) |
| `tests/go_perf_detector_integration.rs` | every `pub use` re-export in PERF detector splits (Phase 4) |
| `tests/go_perf_registry_generation.rs` | the registry TOML split (§5.4) |
| `tests/go_perf_ruleset_audit.rs` | the CWE/PERF audit against `golang.json` |
| `tests/lang_go_detectors_cwe_facts.rs` | the `facts.rs` re-export wildcard (Phase 1 §1.22) |
| `tests/lang_go_detectors_cwe_common.rs` | the `cwe::common::*` path (Phase 3) |
| `tests/engine_cache.rs` (and its 5 split files) | the engine/cache split (Phase 1 §1.2) |
| `tests/app_baseline.rs` (and its 3 split files) | the app/baseline flow (Phase 2 §2.1) |
| `tests/reporting_*.rs` (and their split files) | the reporting splits (Phase 2 §2.6–2.8) |
| `tests/cwe_catalog.rs` | the CWE catalog split (Phase 1 §1.17) |
| `benches/incremental_scan.rs` (and its split) | the bench split (Phase 6 §6.18) |

## Known failure modes to watch for

1. **Forgotten `..` in moved detector files (Phase 3).** When a
   flat detector (`injection.rs`) becomes a directory
   (`injection/sinks.rs`), the `use super::super::…` paths inside
   the moved code become `use super::super::super::…` (one more
   `..` up). The integration test will fail with "cannot find type
   `GoUnitFacts`" or similar.

2. **Forgotten `pub use` in a new `mod.rs`.** The detector
   function is no longer reachable from the registry. The
   integration test will fail with a missing-finding assertion.

3. **Forgotten `cargo:rerun-if-changed` (Phase 5).** The build
   goes stale silently. Mitigation: every directory the build
   script reads is added to the rerun list.

4. **Forgotten `pub(crate)` on shared helpers (Phase 4
   `protocols/common.rs`).** The new sub-files will not compile
   because they cannot import from `common.rs`. The build fails
   loudly with "function `is_flag_call` is private".

5. **Const-fn regression (Phase 3 `metadata_overrides`).** If the
   fan-out in `mod.rs` accidentally calls a non-`const` function in
   const context, the build fails with "calls in constants are
   limited to constant functions". Mitigation: keep every
   `severity_for` / `fix_for` `pub(super) const fn`.

6. **Test path rename missed (Phase 5).** If
   `tests/go_perf_registry_generation.rs` is not updated to
   `read_dir` the new `perf/registry/` directory, the test fails
   immediately at the file read.

## Performance regression checks

The split is structural; no algorithm is changed. Performance should
be within noise:

```bash
# Run the perf regression test
cargo test --test perf_regression --features go,python

# Run the criterion benches (manual, no comparison baseline needed)
cargo bench --features go,python
```

If any benchmark regresses by >5%, investigate the file that changed
— it is likely a non-trivial import that was previously resolved
lazily.

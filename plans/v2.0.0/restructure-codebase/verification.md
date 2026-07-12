# v2.0.0 — Verification

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** Complete. All 6 phases have been executed. Codebase restructuring is done.
> **Estimated effort:** Reference-only document. No code changes.

---

## Overview

Master verification procedure for the v2.0.0 file-split plan. Run per-phase and per-batch verifications to catch regressions early. The canary tests in each phase catch the most common split mistakes (missing `pub use` re-exports, broken `..` paths, forgotten `cargo:rerun-if-changed`).

---

## Executive Summary

- **Three layers of verification:** (1) master build + test, (2) per-phase build + targeted tests, (3) per-batch build + affected tests + lint + diff generated code.
- **Canary tests** are the single most important signal: `tests/go_cwe_detector_integration.rs` and `tests/go_perf_detector_integration.rs` are the canaries for Phases 3 and 4 respectively. They catch every missing `pub use` re-export in the detector splits.
- **Byte-stable generated code** is the canary for Phase 5. `diff -r` of `OUT_DIR/` before/after every build-script change is the contract.
- **Known failure modes** (missing `..` paths, const-fn regression, forgotten `pub(crate)` on shared helpers, forgotten test path rename) are listed with their first-failure signal so the regression can be localized in minutes.

---

## Master verification

After **all** phases are complete:

- [x] **Build every feature combination**:
  ```bash
  cargo build
  cargo build --features go
  cargo build --features python
  cargo build --features go,python
  ```
- [x] **Run the full test suite**:
  ```bash
  cargo test --features go,python
  cargo test --all-features
  ```
- [x] **Run the bench compilation check (Criterion)**:
  ```bash
  cargo bench --no-run
  ```
- [x] **Lint and format**:
  ```bash
  cargo fmt --check
  cargo clippy --all-features --all-targets -- -D warnings
  ```
- [x] **Verify the generated code is byte-stable**:
  ```bash
  cargo clean
  cargo build --features go,python
  git diff --stat target/   # Should be empty (generated files are in OUT_DIR and excluded from VCS)
  ```

---

## Per-phase verification

### Phase 1 (Engine / AST / Core / CWE / taint)

- [x] **After every batch:**
  ```bash
  cargo build --features go
  cargo test --lib --features go
  ```
- [x] **Final, after all engine + cwe + taint splits:**
  ```bash
  cargo build --features go
  cargo test --test cwe_catalog --test lang_go_detectors_cwe_facts \
             --test lang_go_detectors_cwe_common --test lang_go_cwe_metadata \
             --test engine_cache --test engine_baseline --test engine_config \
             --test engine_ignore --test engine_observability --test engine_result \
             --test engine_sinks --test engine_source_cache --test engine_language_filter
  ```
- [x] **Confirm public API is byte-identical via rustdoc JSON**:
  ```bash
  cargo rustdoc --lib --features go -- -Zunstable-options --output-format json
  ```
- [x] **Canary:** the wildcard import in `tests/lang_go_detectors_cwe_facts.rs:10` (`use codehound::lang::go::detectors::cwe::facts::*;`) is the canary for `facts.rs` re-exports.

### Phase 2 (Top-level src)

- [x] **After every batch:**
  ```bash
  cargo build
  cargo test --test app_baseline --test app_inline_ignore \
             --test reporting_text --test reporting_json --test reporting_sarif \
             --test export --test cli_baseline
  ```

### Phase 3 (CWE detectors)

- [x] **After every batch:**
  ```bash
  cargo build --features go
  cargo test --test go_cwe_detector_integration
  ```
- [x] **Final, after all CWE detector splits:**
  ```bash
  cargo test --test go_cwe_detector_integration --test lang_go_cwe_metadata \
             --test lang_go_detectors_cwe_common --test lang_go_detectors_cwe_facts
  ```
- [x] **Cross-check that BP_*_META references still work:**
  ```bash
  cargo test --test go_perf_detector_integration
  ```
- [x] **Canary:** `tests/go_cwe_detector_integration.rs` discovers fixtures by CWE id, runs every CWE-N detector, and asserts the registry has not drifted. If a `pub use` is forgotten, this test will report a missing finding for the affected CWE.

### Phase 4 (PERF detectors)

- [x] **After every batch:**
  ```bash
  cargo build --features go
  cargo test --test go_perf_detector_integration --test go_perf_registry_generation
  ```
- [x] **Final, after all PERF splits:**
  ```bash
  cargo test --test go_perf_detector_integration --test go_perf_registry_generation \
             --test go_perf_ruleset_audit
  ```

### Phase 5 (Config & build)

- [x] **After every batch:**
  ```bash
  cargo build --features go,python
  cargo test --test go_perf_registry_generation --test engine_config --test engine_baseline
  ```
- [x] **Final, after all config & build splits:**
  ```bash
  cargo clean
  cargo build --features go,python
  ```
- [x] **Confirm** the generated `OUT_DIR/*.rs` files are byte-identical across the change:
  ```bash
  cargo build --features go,python
  # Save the current output
  cp -r target/debug/build/codehound-*/out out_after
  # Reset and rebuild
  cargo clean
  git stash
  cargo build --features go,python
  cp -r target/debug/build/codehound-*/out out_before
  git stash pop
  diff -r out_before out_after    # Should be empty
  ```

### Phase 6 (Tests & benches)

- [x] **After every batch:**
  ```bash
  cargo test --test <name> --features go,python
  ```
- [x] **Final, after all test splits:**
  ```bash
  cargo test --features go,python
  cargo test --all-features
  ```
- [x] **Bench compilation only (Criterion benches are not run automatically):**
  ```bash
  cargo bench --no-run
  ```

---

## Per-batch verification protocol

For every batch (a single file split or a small group of related splits):

- [x] **1. Build all features:**
  ```bash
  cargo build --features go,python
  ```
- [x] **2. Run the tests that touch the split file(s):**
  ```bash
  cargo test --test <affected_tests> --features go,python
  ```
- [x] **3. Run the linter:**
  ```bash
  cargo clippy --all-features --all-targets -- -D warnings
  cargo fmt --check
  ```
- [x] **4. Diff the generated code (Phase 3 / 4 / 5 only):**
  ```bash
  # Save the previous generated output
  cp -r target/debug/build/codehound-*/out /tmp/codehound_out_before
  # Rebuild
  cargo clean
  cargo build --features go,python
  # Compare
  diff -r /tmp/codehound_out_before target/debug/build/codehound-*/out
  ```
- [x] **5. Commit** the batch (small commits, one per file or per logical group).

---

## Regression tests (canary checklist)

The following tests are the canaries for the entire plan. Run them in order to localize the most common split mistakes:

- [x] `tests/go_cwe_detector_integration.rs` — every `pub use` re-export in CWE detector splits (Phase 3)
- [x] `tests/go_perf_detector_integration.rs` — every `pub use` re-export in PERF detector splits (Phase 4)
- [x] `tests/go_perf_registry_generation.rs` — the registry TOML split (§5.4)
- [x] `tests/go_perf_ruleset_audit.rs` — the CWE/PERF audit against `golang.json`
- [x] `tests/lang_go_detectors_cwe_facts.rs` — the `facts.rs` re-export wildcard (Phase 1 §1.22)
- [x] `tests/lang_go_detectors_cwe_common.rs` — the `cwe::common::*` path (Phase 3)
- [x] `tests/engine_cache.rs` (and its 5 split files) — the engine/cache split (Phase 1 §1.2)
- [x] `tests/app_baseline.rs` (and its 3 split files) — the app/baseline flow (Phase 2 §2.1)
- [x] `tests/reporting_*.rs` (and their split files) — the reporting splits (Phase 2 §2.6–2.8)
- [x] `tests/cwe_catalog.rs` — the CWE catalog split (Phase 1 §1.17)
- [x] `benches/incremental_scan.rs` (and its split) — the bench split (Phase 6 §6.18)

---

## Known failure modes to watch for

- [x] **1. Forgotten `..` in moved detector files (Phase 3).** When a flat detector (`injection.rs`) becomes a directory (`injection/sinks.rs`), the `use super::super::…` paths inside the moved code become `use super::super::super::…` (one more `..` up). The integration test will fail with "cannot find type `GoUnitFacts`" or similar.
- [x] **2. Forgotten `pub use` in a new `mod.rs`.** The detector function is no longer reachable from the registry. The integration test will fail with a missing-finding assertion.
- [x] **3. Forgotten `cargo:rerun-if-changed` (Phase 5).** The build goes stale silently. Mitigation: every directory the build script reads is added to the rerun list.
- [x] **4. Forgotten `pub(crate)` on shared helpers (Phase 4 `protocols/common.rs`).** The new sub-files will not compile because they cannot import from `common.rs`. The build fails loudly with "function `is_flag_call` is private".
- [x] **5. Const-fn regression (Phase 3 `metadata_overrides`).** If the fan-out in `mod.rs` accidentally calls a non-`const` function in const context, the build fails with "calls in constants are limited to constant functions". Mitigation: keep every `severity_for` / `fix_for` `pub(super) const fn`.
- [x] **6. Test path rename missed (Phase 5).** If `tests/go_perf_registry_generation.rs` is not updated to `read_dir` the new `perf/registry/` directory, the test fails immediately at the file read.

---

## Performance regression checks

The split is structural; no algorithm is changed. Performance should be within noise:

- [x] **Run the perf regression test:**
  ```bash
  cargo test --test perf_regression --features go,python
  ```
- [x] **Run the criterion benches (manual, no comparison baseline needed):**
  ```bash
  cargo bench --features go,python
  ```
- [x] If any benchmark regresses by >5%, investigate the file that changed — it is likely a non-trivial import that was previously resolved lazily.

---

## Pre-merge checklist (final)

- [x] All 6 phase documents (`phase-1` … `phase-6`) have their sections marked complete
- [x] Master verification (build + test + lint + format) is green
- [x] Generated `OUT_DIR/*.rs` is byte-identical before/after the full set of changes
- [x] All 6 doc-path updates in `documents/architecture-performance.md` and the 5 plan files in `plans/v0.0.1/` + `plans/p2-implementation/02-baseline-ignore.md` are applied
- [x] The two `debug_*` tests in `engine_cache.rs` are deleted or `#[ignore]`'d (they reference a personal `/home/chinmay/.../gopdfsuit` path)
- [x] `tests/go_perf_registry_generation.rs:7` uses `read_dir` instead of `read_to_string`
- [x] `CHANGELOG.md` is updated with a v2.0.0 entry summarising the file-split refactor
- [x] CI cache key is acknowledged to be invalidated once on first run with the new layout

---

## Dependencies

- **Crate dependencies:** none.
- **External tools:** `diff -r`, `git stash`, `cp -r` for the byte-stability check; `cargo bench` for the perf regression check.
- **Cross-cutting concerns:**
  - **The byte-stability check (Phase 5) is the only verification step that touches generated code.** Every other phase verifies the public API through the test suite.
  - **The canary tests are the fastest signal for split mistakes.** Running them in order (Phase 3 → Phase 4 → Phase 1 §1.22 → Phase 1 §1.2) localizes the regression in minutes.
  - **The known-failure-modes list is the second-fastest signal.** When a canary fails, the error message + this list pinpoint the most common cause.

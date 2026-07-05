# Consolidated Pending Tasks — 2026-07-05

> **Status:** Verified "not implemented" items across all workstreams (codebase-audited 2026-07-05)
> **Estimated effort:** ~10–12 weeks total across all workstreams

---

## Overview

Verified list of genuinely unimplemented items — each claim cross-checked against the actual codebase.
Items marked "not started" in plan documents that are actually implemented are excluded.

---

## Executive Summary

| Workstream | Priority | Status | Remaining Effort | Key Deliverable |
|------------|----------|--------|-----------------|-----------------|
| Fix Engine | P0 | ⏸️ Planned — deferred | — | `--fix`/`--fix-dry-run`, 38 safe fixers, edit engine |
| Cache Config + Tests | P1 | ⚠️ Partial | 1 week | `evict_target_ratio`, `max_file_size_mb`, 4 missing tests, eviction logging |
| Taint Reporting | P1 | ⚠️ Partial | 2–3 days | JSON/SARIF `taint_show_paths` wire-up |
| CI/CD + Test Hygiene | P2 | ✅ Done | — | GitHub Actions bench CI gate, real-world smoke fixtures, clean-Go verification |
| Cross-cutting Docs | P2 | ✅ Done | — | `docs/perf-rules.md`, README refs, CHANGELOG, schema/template updates, `--diagnostics-summary` |
| BP Prose Fixes | P3 | ⚠️ Partial | 1 day | `fix_for()` for BP-16..BP-65 |
| Phase 5 Confidence Score | P4 | ❌ Not started | 2–3 weeks | Confidence scoring for taint paths |
| Rule-Pack Extensibility | P4 | ❌ Not started | TBD | External rule-pack loading (scoping done) |
| Deprecate `engine::*` re-exports | P4 | ❌ Not started | 1 day | Public surface narrowing |

---

## P0 — Fix Engine (implement-fix.md) ⏸️ DEFERRED

> **Parent:** `plans/v2.0.0/implement-fix.md`
> **Status:** ⏸️ Planned — deferred. Zero fix-engine infrastructure exists. All 38 safe-fixer detectors exist as detection-only.
> **Decision:** Not implementing for now. The detector-only mode is sufficient. Revisit when users explicitly request auto-fix.
> **Estimated effort:** 4–6 weeks (if picked up)

### Phase 0 — Rule/Detector Integrity (before engine build)

- [ ] Add schema/coverage test that fails on: extra fields, mixed id formats (string vs int), duplicate IDs, missing registry entries, stale "Draft" status on PERF-101..212, fixture-metadata mismatch
- [ ] Normalize PERF id representation (PERF-001 string, PERF-101 integer — pick one)
- [ ] Update stale statuses (Draft → Implemented) for PERF-101..212
- [ ] Mark 3 intentionally-unregistered PERF rules explicitly (PERF-104, 136, 208)

### Phase 1 — Minimal Safe Edit Engine

- [ ] Add `Applicability` enum (`MachineApplicable`, `RequiresReview`) and `SourceEdit` struct
- [ ] Add `--fix` CLI flag (`src/cli/args.rs`)
- [ ] Add `--fix-dry-run` CLI flag
- [ ] Wire fix-mode incompatibility with `--baseline`, `--list-rules`, `--explain`, cache-pruning
- [ ] Force fresh uncached scan in fix mode
- [ ] Implement source hash validation, dedup, conflict detection, offset-sorted application
- [ ] Implement in-memory apply + gofmt + reparse + atomic write
- [ ] Promote `write_atomic` from `pub(super)` in `src/engine/cache/io.rs` to general-use
- [ ] Implement deterministic import insertion/removal with alias detection
- [ ] Report: files changed, edits applied/skipped, conflicts, findings remaining
- [ ] Compute exit code from post-fix rescan

### Phase 2 — 38 Safe Default Fixers

All detectors exist. Fixers need structured `SourceEdit` output:

- [ ] **Hoisting/reuse (11):** PERF-001, 016, 024, 044, 096, 109, 141, 153, 179, 192, 203
- [ ] **Stdlib substitution (12):** PERF-042, 111, 115, 116, 117, 120, 124, 126, 127, 146, 147, 178
- [ ] **Syntax/control-flow rewrite (15):** PERF-103, 113, 114, 119, 121, 122, 123, 128, 129, 130, 133, 158, 167, 173
- [ ] **BP safe fixer (1):** BP-6 — WaitGroup Add Inside Goroutine

### Phase 3 — 138 Review-Required Patch Candidates

All detectors exist. No structured patches. Add policy/precondition gate:

- [ ] 91 PERF review-required (5 groups)
- [ ] 40 CWE review-required (CWE-78, 79, 89, 93, 178…1392)
- [ ] 7 BP review-required (BP-2, 4, 5, 7, 10, 11, 13)

### Phase 4 — Verification

- [ ] Golden transformed-source fixtures per fixer
- [ ] Refusal fixtures (non-applicable patterns produce no edit)
- [ ] Parse+gofmt check on every transformed output
- [ ] Rescan assertion (post-fix findings drop to zero for the fixed rule)
- [ ] Idempotence test (running fix twice produces same result)
- [ ] Go compilation test on transformed output
- [ ] Edit-engine test categories (overlapping edits, dedup, hash rejection, UTF-8, CRLF, formatter failure, atomic-write failure, dry-run, filters, baseline incompatibility)
- [ ] Benchmark normal scans before/after edit payload support
- [ ] Document `--fix`, `--fix-dry-run`, safety guarantees

---

## P1 — Cache Config + Tests + Eviction Logging

> **Parent:** `plans/v2.0.0/pending-work/04-cache-incremental-remaining.md`
> **Status:** Core cache infrastructure done. Config fields, logging, and 4 tests missing.
> **Estimated effort:** 1 week

### Config Fields

- [x] Add `evict_target_ratio: Option<f64>` to `CacheConfig` (default 0.9)
- [x] Wire through `CacheStore::open_with_capacity()` and use in `evict_to_size()`
- [x] Validate range (0.1–0.99) with `tracing::warn!` on out-of-range (clamp to 0.9)
- [x] Add `max_file_size_mb: Option<u64>` to `CacheConfig` (default 4)
- [x] In scan preflight/cache-lookup, skip caching for files larger than threshold
- [x] Log `tracing::debug!` when file skipped due to size
- [x] Update `slopguard.schema.json` with both new fields
- [x] Update `docs/incremental-cache.md` with both new config options

### Eviction Logging

- [x] In `CacheStore::evict_to_size()`, emit `tracing::info!` with `entries_evicted`, `bytes_freed`, `current_size_mb`, `target_size_mb`

### Missing Tests

- [x] Concurrent scans test (`tests/engine_cache_concurrent.rs`)
- [x] Transitive invalidation without `go.mod` (cwd fallback path)
- [x] Tool version mismatch (code handles it, no test)
- [x] Corrupt entry file (code handles it, no test)
- [x] `clean_orphans()` dedicated test

---

## P1 — Taint Reporting: JSON/SARIF `taint_show_paths`

> **Parent:** `plans/v2.0.0/pending-work/05-cross-cutting-remaining.md` §2.1
> **Status:** CLI flag exists (`--taint-show-paths`), text reporter wired, JSON and SARIF not.
> **Estimated effort:** 2–3 days

- [x] Wire `taint_show_paths` into JSON reporter (`src/reporting/json/entry.rs`)
- [x] Wire `taint_show_paths` into SARIF reporter (`properties` bag)

---

## P2 — CI/CD + Test Hygiene

> **Parent:** `plans/v2.0.0/pending-work/05-cross-cutting-remaining.md` §3
> **Status:** ✅ Done. Incremental bench CI gate added, real-world smoke fixtures, clean Go file verification test.
> **Estimated effort:** 1 week

### Incremental Benchmark CI Gate

- [x] Add `cargo bench --bench incremental_scan` to `.github/workflows/ci.yml`
- [x] Create `scripts/check_incremental_bench_budget.sh` (assert warm ≥5× faster than cold)
- [x] Document in `benchmarks.md`

### Real-World Smoke Fixtures

- [x] Create `tests/fixtures/go/perf_real_world/` with realistic HTTP server triggering ≥3 PERF rules
- [x] Create safe variant with idiomatic fixes — verify zero findings
- [x] Add integration test + register in `manifest.toml`

### Clean Go File Verification

- [x] Create `tests/fixtures/go/perf_real_world/clean_go_file.txt` (~50–100 lines, correct stdlib usage)
- [x] Run all shipped PERF + BP + CWE detectors against it, verify zero false positives

---

## P2 — Cross-Cutting Docs + Schema

> **Parent:** `plans/v2.0.0/pending-work/05-cross-cutting-remaining.md` §1, §2.2, §2.3, §4, §5
> **Status:** ✅ Done. `docs/perf-rules.md` created, README/CHANGELOG/schema/template updated, `--diagnostics-summary` wired.
> **Estimated effort:** 3–4 days

### `--diagnostics-summary` CLI Flag

- [x] Add `--diagnostics-summary` flag (no argument) to `src/cli/args.rs`
- [x] Wire to output `ScanStats` (`files_scanned`, `cache_hits`, `cache_misses`, `slowest_detector`, `total_time`)
- [x] Works with both `scan` and `--list-rules`
- [x] Add to `--help` output

### Documentation

- [x] Create `docs/perf-rules.md` — one paragraph per shipped PERF rule with fix example
- [x] Add README.md cross-references to `docs/taint.md`, `docs/bad-practices.md`, `docs/perf-rules.md`

### CHANGELOG

- [x] Add entries under Unreleased for `--diagnostics-summary` and CI/CD + test hygiene

### Schema + Config Template

- [x] Add `cache.evict_target_ratio` to `slopguard.schema.json` *(already present, verified)*
- [x] Add `cache.max_file_size_mb` to `slopguard.schema.json` *(already present, verified)*
- [x] Add `bad_practices.severity_overrides` to `slopguard.schema.json`
- [x] Add `[slopguard.bad_practices]` with `severity_overrides` to `templates/slopguard.toml`
- [x] Add `cache.evict_target_ratio` and `cache.max_file_size_mb` to `templates/slopguard.toml`

### Per-Detector Timing on Cache Hit *(still pending — needs CacheEntry struct changes)*

- [ ] Add `original_detect_duration_ms` to `CacheEntry` struct
- [ ] Add `TimingSpan` for cache-hit path (file read, filter, ignore re-apply, saved time)
- [ ] Emit in `--diagnostics` and `--debug-timing` output

---

## P3 — BP Prose Fixes (BP-16..BP-65)

> **Parent:** `plans/v2.0.0/pending-work/03-bad-practices-remaining.md`
> **Status:** All 65 detectors + fixtures + tests implemented. `fix_for()` only covers BP-1..BP-15.
> **Estimated effort:** 1 day

- [ ] Add `fix_for()` prose suggestions for BP-16 through BP-65 in `metadata_overrides.rs`

---

## P4 — Lower Priority

### Phase 5 Confidence Scoring

> **Status:** ❌ Not started. No confidence scoring, hop-count-based decay, or severity downgrading exists.
> **Estimated effort:** 2–3 weeks

- [ ] `confidence: f32` on `Finding`
- [ ] Hop-count-based confidence decay in taint BFS
- [ ] Severity downgrading for long/speculative paths

### Rule-Pack Extensibility

> **Parent:** `plans/p2-implementation/missing-D-rule-pack-extensibility.md`
> **Status:** Scoping complete. Zero implementation.
> **Estimated effort:** TBD

- [ ] External rule-pack loading (metadata-only packs, registry TOML + fixtures, WASM detectors)
- [ ] CLI flag for pack directory
- [ ] Sandboxed evaluation

### Public Surface Narrowing

> **Parent:** `plans/v2.0.0/antipattern-remediation/rust-remediation-phase-2.md` §2D.1
> **Status:** ❌ Not started.

- [ ] Deprecate direct `engine::*` re-exports
- [ ] Update `src/main.rs` to use `slopguard::cli` via feature gate

---

## Dependency Graph

```
P0 (Fix Engine — implement-fix.md)
  └─ independent of other workstreams
  └─ Phase 0 (schema/coverage test) is prerequisite for Phase 1

P1 (Cache config + tests)
  └─ independent, can parallel with P1 taint reporting

P1 (Taint JSON/SARIF wire-up)
  └─ depends on `--taint-show-paths` CLI flag ✅ DONE

P2 (CI/CD + test hygiene)
  └─ depends on nothing

P2 (Cross-cutting docs + schema)
  └─ docs depend on feature completion ✅ DONE (features exist)
  └─ schema/template updates are independent

P3 (BP prose fixes)
  └─ independent

P4 (Confidence scoring)
  └─ depends on taint graph infrastructure ✅ DONE

P4 (Rule-pack extensibility)
  └─ depends on detector trait infrastructure ✅ DONE

P4 (Public surface narrowing)
  └─ independent
```

## Quick Reference

| Priority | Workstream | Items | Effort | Blocked By |
|----------|-----------|-------|--------|------------|
| **P0** | Fix Engine | implement-fix.md all phases | ⏸️ Deferred | — |
| **P1** | Cache config + tests | `evict_target_ratio`, `max_file_size_mb`, 4 tests, eviction logging | 1w | — |
| **P1** | Taint reporting | JSON/SARIF `taint_show_paths` | 2–3d | `--taint-show-paths` ✅ |
| **P2** | CI/CD + test hygiene | Bench CI gate, real-world smoke fixtures, clean-Go-file | 1w | — |
| **P2** | Cross-cutting docs | `docs/perf-rules.md`, README refs, CHANGELOG, schema/template | 3–4d | — |
| **P2** | `--diagnostics-summary` | New CLI flag | 1d | — |
| **P3** | BP prose fixes | `fix_for()` BP-16..BP-65 | 1d | — |
| **P4** | Confidence scoring | Phase 5 taint scoring | 2–3w | Taint graph ✅ |
| **P4** | Rule-pack extensibility | External pack loading | TBD | Detector infra ✅ |
| **P4** | Public surface narrowing | Deprecate `engine::*` re-exports | 1d | — |

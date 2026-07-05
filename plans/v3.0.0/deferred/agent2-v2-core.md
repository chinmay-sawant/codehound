# D2 — V2 Core Deferred

> **Parent:** `plans/v2.0.0/`
> **Status:** 82 items deferred to v3.0.0, 5 resolved since initial audit
> **Estimated effort:** TBD

---

## Overview

Deferred items from 8 plan files under `plans/v2.0.0/` that were not yet implemented at time of audit (2026-07-05).

---

## Phase 1: Fix Engine (implement-fix.md)

Zero fix-engine infrastructure exists. All 38 safe-fixer detectors exist as detection-only. Deferred until users explicitly request auto-fix.

### 1.1 Rule/Detector Integrity

- [ ] Remove 112 nested PERF-101..212 objects inside PERF-100 in JSON
- [ ] Require exactly ten fields on every top-level entry
- [ ] Normalize PERF id representation
- [ ] Verify top-level key / embedded id match
- [ ] Update stale Draft statuses for PERF-101..212
- [ ] Keep 3 unregistered PERF rules explicit
- [ ] Build rule→detector→fixture inventory
- [ ] Fix semantic mismatches (PERF-102)
- [ ] Fixture asserts JSON rule name
- [ ] Verify 175 CWE registry entries
- [ ] Move 13 shipped BP definitions to bad-practices.json
- [ ] Schema/coverage test
- [ ] Run registry check in cargo test + CI

### 1.2 Minimal Safe Edit Engine

- [ ] Applicability enum + SourceEdit struct
- [ ] Emit edit only from exact AST match
- [ ] Keep fixes optional
- [ ] `--fix` CLI flag
- [ ] `--fix-dry-run` CLI flag
- [ ] Honor filters before planning edits
- [ ] Fix mode incompatible with baseline / list-rules / explain / cache-pruning
- [ ] Force fresh uncached scan in fix mode
- [ ] Report files changed / edits applied/skipped / conflicts
- [ ] Compute exit code from post-fix rescan
- [ ] Source hash + expected-text validation
- [ ] Dedup identical edits
- [ ] Reject overlapping non-identical edits
- [ ] Sort accepted edits by descending byte offset
- [ ] Apply all edits in memory
- [ ] gofmt on in-memory result
- [ ] Reparse formatted result with tree-sitter
- [ ] Reuse/generalize write_atomic
- [ ] Invalidate cache entries for changed files
- [ ] Rescan changed files; fail if finding persists
- [ ] Deterministic import insertion/removal
- [ ] Detect aliases, dot imports, blank imports, shadows
- [ ] Decline when import resolution is ambiguous
- [ ] Let gofmt format the result

### 1.3 Safe Default Fixers

- [ ] PERF-001, 016, 024, 044, 096, 109, 141, 153, 179, 192, 203 (hoisting/reuse)
- [ ] PERF-042, 111, 115, 116, 117, 120, 124, 126, 127, 146, 147, 178 (stdlib substitution)
- [ ] PERF-103, 113, 114, 119, 121, 122, 123, 128, 129, 130, 133, 158, 167, 173 (syntax/control-flow rewrite)
- [ ] BP-6 (WaitGroup Add Inside Goroutine)

### 1.4 Review-Required Patch Candidates

- [ ] 91 PERF review-required (5 groups)
- [ ] 40 CWE review-required (CWE-78..CWE-1392)
- [ ] 7 BP review-required (BP-2, 4, 5, 7, 10, 11, 13)

### 1.5 Verification

- [ ] Golden transformed-source fixtures per fixer
- [ ] Refusal fixtures
- [ ] Parse+gofmt check
- [ ] Rescan assertion (post-fix findings zero)
- [ ] Idempotence test
- [ ] Go compilation test
- [ ] Edit-engine tests (overlapping, dedup, hash rejection, UTF-8, CRLF, formatter/parser failure, atomic-write, read-only, dry-run, filters)
- [ ] Benchmark normal scans before/after edit payload
- [ ] Benchmark fix planning/application
- [ ] `cargo fmt`, focused tests, all-features, lint checks, real Go project dry-run
- [ ] Document `--fix` / `--fix-dry-run` / safety guarantees

---

## Phase 2: Archive & CI

### 2.1 Archive Step

- [ ] Archive `plans/perf-batch-4.md` → `plans/v2.0.0/archive/`

### 2.2 CI/Tests

- [ ] Add `cargo test --all-features` run with taint enabled to CI

---

## Phase 3: Taint Tracking

### 3.1 Core Taint

- [ ] Incremental cache storage for taint summaries (compute on every finalize() for now)
- [ ] `lazy_static! BUILTIN_SUMMARIES` for stdlib functions (opaque-call heuristic covers most)
- [ ] Dedicated `merge_taint_graphs()` with offset-adjusted IDs (current approach rebuilds per-file graphs)
- [ ] `max_depth` parameter for BFS (graph is shallow enough without it)
- [ ] `TaintNode::Return` nodes not yet created by extractor (detected via source-text scan instead)

### 3.2 Edge Cases

- [ ] ponytail depth cap, widening, and `recursive: true` evidence flag
- [ ] Struct field mutations (`(*p).field = source()`)
- [ ] `*p = tainted_var` (callee writes tainted variable, not source call)

---

## Phase 4: Cache & Performance

- [ ] Store inline-ignore set inside cache entry
- [ ] Detect dependencies-list change on identical content hash
- [x] Narrower transitive invalidation test (no go.mod) — implemented
- [x] Concurrent process cache corruption test — implemented
- [ ] Performance verification / criterion bench regression investigation
- [ ] Tighten PERF-198 with `textproto.MIMEType` parsing

---

## Phase 5: Bad Practices & Cross-Cutting

### 5.1 BP Fix Prose

- [ ] `fix_for()` prose suggestions for BP-16 through BP-65 in `metadata_overrides.rs`

### 5.2 P2.5 BP Items

- [x] Add per-rule severity overrides for bad practices
- [ ] HTML reporter (render BP findings with color band)
- [ ] Negative fixtures (almost-but-not-quite patterns)
- [ ] BP-15 regression test (separate function closure in sync.Once.Do)

### 5.3 Cross-Cutting Timing

- [ ] Per-detector timing on cache hit (`original_detect_duration_ms` on `CacheEntry`, `TimingSpan` for cache-hit path)
- [ ] Add per-detector timing to the cache hit path (overlaps with item above — see `consolidated_pendingtask_05072026.md` P1)

---

## Phase 6: Lower Priority

- [x] `confidence: f32` on Finding (hop-count decay and severity downgrade remain deferred)
- [ ] External rule-pack loading, CLI flag for pack directory, sandboxed evaluation
- [ ] Deprecate direct `engine::*` re-exports
- [x] Update `src/main.rs` to use `slopguard::cli` via feature gate

---

## Summary

| Status | Count |
|--------|-------|
| `[x]` Implemented | 5 |
| `[ ]` Not implemented | 77 |
| **Total** | **82** |

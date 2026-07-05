# Deferred Items — Agent2 V2 Core Audit

> **Auto-generated from plan-file audit (2026-07-05)**
> **Source files:** 8 plan files under `plans/v2.0.0/`
> **Each item:** source plan → item description → deferred note

---

## Fix Engine (implement-fix.md) — all phases deferred

**Parent:** `plans/v2.0.0/implement-fix.md`
**Decision:** Zero fix-engine infrastructure exists. All 38 safe-fixer detectors exist as detection-only. Deferred until users explicitly request auto-fix.

### Phase 0 — Rule/Detector Integrity
- `implement-fix.md` §0.1: Remove 112 nested PERF-101..212 objects inside PERF-100 in JSON
- `implement-fix.md` §0.1: Require exactly ten fields on every top-level entry
- `implement-fix.md` §0.1: Normalize PERF id representation
- `implement-fix.md` §0.1: Verify top-level key / embedded id match
- `implement-fix.md` §0.1: Update stale Draft statuses for PERF-101..212
- `implement-fix.md` §0.1: Keep 3 unregistered PERF rules explicit
- `implement-fix.md` §0.2: Build rule→detector→fixture inventory
- `implement-fix.md` §0.2: Fix semantic mismatches (PERF-102)
- `implement-fix.md` §0.2: Fixture asserts JSON rule name
- `implement-fix.md` §0.2: Verify 175 CWE registry entries
- `implement-fix.md` §0.2: Move 13 shipped BP definitions to bad-practices.json
- `implement-fix.md` §0.3: Schema/coverage test
- `implement-fix.md` §0.3: Run registry check in cargo test + CI

### Phase 1 — Minimal Safe Edit Engine
- `implement-fix.md` §1.1: Applicability enum + SourceEdit struct
- `implement-fix.md` §1.1: Emit edit only from exact AST match
- `implement-fix.md` §1.1: Keep fixes optional
- `implement-fix.md` §1.2: --fix CLI flag
- `implement-fix.md` §1.2: --fix-dry-run CLI flag
- `implement-fix.md` §1.2: Honor filters before planning edits
- `implement-fix.md` §1.2: Fix mode incompatible with baseline / list-rules / explain / cache-pruning
- `implement-fix.md` §1.2: Force fresh uncached scan in fix mode
- `implement-fix.md` §1.2: Report files changed / edits applied/skipped / conflicts
- `implement-fix.md` §1.2: Compute exit code from post-fix rescan
- `implement-fix.md` §1.3: Source hash + expected-text validation
- `implement-fix.md` §1.3: Dedup identical edits
- `implement-fix.md` §1.3: Reject overlapping non-identical edits
- `implement-fix.md` §1.3: Sort accepted edits by descending byte offset
- `implement-fix.md` §1.3: Apply all edits in memory
- `implement-fix.md` §1.3: gofmt on in-memory result
- `implement-fix.md` §1.3: Reparse formatted result with tree-sitter
- `implement-fix.md` §1.3: Reuse/generalize write_atomic
- `implement-fix.md` §1.3: Invalidate cache entries for changed files
- `implement-fix.md` §1.3: Rescan changed files; fail if finding persists
- `implement-fix.md` §1.4: Deterministic import insertion/removal
- `implement-fix.md` §1.4: Detect aliases, dot imports, blank imports, shadows
- `implement-fix.md` §1.4: Decline when import resolution is ambiguous
- `implement-fix.md` §1.4: Let gofmt format the result

### Phase 2 — 38 Safe Default Fixers
- `implement-fix.md` §2.1: PERF-001, 016, 024, 044, 096, 109, 141, 153, 179, 192, 203 (hoisting/reuse)
- `implement-fix.md` §2.2: PERF-042, 111, 115, 116, 117, 120, 124, 126, 127, 146, 147, 178 (stdlib substitution)
- `implement-fix.md` §2.3: PERF-103, 113, 114, 119, 121, 122, 123, 128, 129, 130, 133, 158, 167, 173 (syntax/control-flow rewrite)
- `implement-fix.md` §2.4: BP-6 (WaitGroup Add Inside Goroutine)

### Phase 3 — 138 Review-Required Patch Candidates
- `implement-fix.md` §3.1: 91 PERF review-required (5 groups)
- `implement-fix.md` §3.2: 40 CWE review-required (CWE-78..CWE-1392)
- `implement-fix.md` §3.3: 7 BP review-required (BP-2, 4, 5, 7, 10, 11, 13)

### Phase 4 — Verification
- `implement-fix.md` §4.1: Golden transformed-source fixtures per fixer
- `implement-fix.md` §4.1: Refusal fixtures
- `implement-fix.md` §4.1: Parse+gofmt check
- `implement-fix.md` §4.1: Rescan assertion (post-fix findings zero)
- `implement-fix.md` §4.1: Idempotence test
- `implement-fix.md` §4.1: Go compilation test
- `implement-fix.md` §4.2: Edit-engine tests (overlapping, dedup, hash rejection, UTF-8, CRLF, formatter/parser failure, atomic-write, read-only, dry-run, filters)
- `implement-fix.md` §4.3: Benchmark normal scans before/after edit payload
- `implement-fix.md` §4.3: Benchmark fix planning/application
- `implement-fix.md` §4.3: cargo fmt, focused tests, all-features, lint checks, real Go project dry-run
- `implement-fix.md` §4.3: Document --fix / --fix-dry-run / safety guarantees

---

## Archive Step

- `02-ruleset-split-and-perf-213-224.md` §6.2: Archive `plans/perf-batch-4.md` → `plans/v2.0.0/archive/`

---

## CI/Tests

- `consolidated_pendingtask_02072026.md` P1-C: Add `cargo test --all-features` run with taint enabled to CI

---

## Taint Tracking — Deferred Items

- `p1f-inter-procedural-taint.md` §2.3: Incremental cache storage for taint summaries (compute on every finalize() for now)
- `p1f-inter-procedural-taint.md` §2.4: `lazy_static! BUILTIN_SUMMARIES` for stdlib functions (opaque-call heuristic covers most)
- `p1f-inter-procedural-taint.md` §3.2: Dedicated `merge_taint_graphs()` with offset-adjusted IDs (current approach rebuilds per-file graphs)
- `p1f-inter-procedural-taint.md` §3.3: `max_depth` parameter for BFS (graph is shallow enough without it)
- `p1f-inter-procedural-taint.md` §3.3: `TaintNode::Return` nodes not yet created by extractor (detected via source-text scan instead)

---

## Taint Edge Cases

- `p1f-phase6-edge-cases.md` §6.1: ponytail depth cap, widening, and `recursive: true` evidence flag
- `p1f-phase6-edge-cases.md` §6.2 Track B: struct field mutations (`(*p).field = source()`)
- `p1f-phase6-edge-cases.md` §6.2 Track B: `*p = tainted_var` (callee writes tainted variable, not source call)

---

## Cache / Perf — Deferred Items

- `p2-remaining-work.md` §A.1 Phase 4.2: Store inline-ignore set inside cache entry
- `p2-remaining-work.md` §A.1 Phase 4.3: Detect dependencies-list change on identical content hash
- `p2-remaining-work.md` §A.1 Phase 8.2: Narrower transitive invalidation test (no go.mod) — **(now implemented)** via `transitive_invalidation_works_without_go_mod_using_cwd_fallback_paths` in `tests/engine_cache_invalidation.rs`
- `p2-remaining-work.md` §A.1 Phase 8.4: Concurrent process cache corruption test — **(now implemented)** via `concurrent_scans_can_share_a_cache_directory_without_panicking` in `tests/engine_cache_concurrent.rs`
- `p2-remaining-work.md` §B.1 Phase 5: Performance verification / criterion bench regression investigation
- `p2-remaining-work.md` §B.2: Tighten PERF-198 with `textproto.MIMEType` parsing

---

## Cross-Cutting — Deferred Items

- `consolidated_pendingtask_05072026.md` P1: Per-detector timing on cache hit (`original_detect_duration_ms` on `CacheEntry`, `TimingSpan` for cache-hit path)
- `p2-remaining-work.md` §E.5: Add per-detector timing to the cache hit path

---

## BP Fix Prose

- `consolidated_pendingtask_05072026.md` P3: `fix_for()` prose suggestions for BP-16 through BP-65 in `metadata_overrides.rs`

---

## P2.5 BP — Deferred Items

- `p2-remaining-work.md` §C.2: Add per-rule severity overrides for bad practices — **(now implemented)** per-rule `severity_overrides` in schema; global `bad_practice_severity` on `ScanContext` (+ config wiring) in code
- `p2-remaining-work.md` §C.3: HTML reporter (render BP findings with color band)
- `p2-remaining-work.md` §C.4: Negative fixtures (almost-but-not-quite patterns)
- `p2-remaining-work.md` §C.5: BP-15 regression test (separate function closure in sync.Once.Do)

---

## P4 — Lower Priority

- `consolidated_pendingtask_05072026.md` P4 (Confidence): `confidence: f32` on Finding — **(now implemented)** on `Finding` struct + JSON/SARIF/text rendering. Hop-count-based decay and severity downgrading remain deferred.
- `consolidated_pendingtask_05072026.md` P4 (Rule-Pack): External rule-pack loading, CLI flag for pack directory, sandboxed evaluation
- `consolidated_pendingtask_05072026.md` P4 (Public Surface): Deprecate direct `engine::*` re-exports — **(still deferred)**. Update `src/main.rs` to use `slopguard::cli` via feature gate — **(now implemented)**

# v0.0.3 — Rust Quality Remediation Checklist

> **Parent:** `v0.0.3/codex-review.md` — consolidated Rust review and implementation ledger
> **Status:** Phase 1 complete; Phase 2 remains
> **Date:** 2026-07-15
> **Goal:** Rust Best Practices **9.5+/10** and Rust Development Patterns **9.5+/10**

---

## Overview

This is the live implementation checklist for the four-agent Rust review of CodeHound. Scope is Rust code only: `src/`, `build.rs`/`build/`, `tests/`, `benches/`, and Rust-facing Cargo configuration.

Review skills used:

- Repository-local `rust-best-practices` — Apollo-style ownership, errors, performance, linting, testing, dispatch, and documentation.
- Repository-local `rust-patterns` — Rust Development Patterns for ownership, type modeling, error boundaries, concurrency, module design, and minimal public APIs.

No MCP tools, graph tools, web access, or source-code edits were used during the review. Implementation changes are now being made phasewise from this file.

## Baseline Scores and Acceptance Gates

| Review | Baseline | Target | Current gate |
|---|---:|---:|---|
| Rust Best Practices | **6.8/10** | **9.5+/10** | Clippy, fmt, tests, ownership/error/perf/docs evidence green |
| Rust Development Patterns | **7.5/10** | **9.5+/10** | Scan lifecycle, cache correctness, concurrency, API invariants, and tests green |

### Baseline evidence

- [x] Four independent read-only Rust review passes completed.
- [x] Strengths recorded: typed core errors, `Arc<str>`, parser pooling, Rayon dispatch, useful enums, justified dynamic dispatch, no Rust `unsafe`, and broad tests.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` reproduced two denied `unwrap()` failures in `src/engine/ignore/parse.rs:111` and `:115`.
- [x] `cargo fmt --all -- --check` reproduced formatting drift in eight Rust files.
- [x] Serial all-feature testing reproduced three stale source-cache contract failures in `tests/engine_source_cache_edge.rs`.
- [x] Parallel testing exposed timing-test interference around the process-global timing collector; the same timing test passed in isolation.
- [x] Performance-only Clippy completed without `clippy::perf` findings when the existing deny gate was capped for diagnosis.

## Phase 1 — Gate Recovery and Contract Alignment

### 1.1 Formatting and lint gate

- [x] Run `cargo fmt --all` and verify `cargo fmt --all -- --check`.
- [x] Remove the two production `unwrap()` calls without weakening `#![deny(clippy::unwrap_used)]`.
- [x] Verify `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [ ] Confirm no new `#[allow]` suppressions are introduced; use `#[expect]` only with a reason when unavoidable.

### 1.2 Source-cache contract

The memory-saving design is intentional: default CI/JSON/SARIF runs use `retain_sources: false`; export modes opt in. The tests must express that contract explicitly.

- [x] Update `AnalysisResult.source_cache` documentation to state that it is populated only when `ScanContext.retain_sources` is true.
- [x] Set `retain_sources: true` in source-cache edge/population/export tests that specifically exercise retained sources.
- [x] Preserve the test proving the default path does not retain source text (`tests/profile_packs.rs`).
- [x] Run `cargo test --all-features --locked --test engine_source_cache_edge --test engine_source_cache_populate --test engine_source_cache_export`.

### 1.3 Cached result accounting

- [~] Investigate suppression count preservation. Cache entries are written after inline-ignore filtering, so a cache hit cannot reconstruct the original count without a cache-schema change; no misleading partial fix was retained.
- [ ] Decide whether to persist suppression metadata or define cached suppression statistics as post-cache filtering only.
- [ ] Add a regression test after that contract decision.

### Phase 1 acceptance

- [x] `cargo fmt --all -- --check` passes.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [x] Source-cache focused tests pass.
- [x] No behavior change to default memory-saving source retention.
- [x] Full serial all-feature test suite passes with `--test-threads=1`.

## Phase 2 — Scan Correctness and Lifecycle Safety

### 2.1 Scan-scoped timing

- [ ] Replace process-global timing state with scan-owned or worker-local collectors merged at the analyzer boundary.
- [ ] Ensure timing survives every scan chunk and is not disabled after the first drain.
- [ ] Add a multi-chunk timing regression test.
- [ ] Add a concurrent-analyzer timing isolation test.
- [ ] Ensure timing instrumentation does not serialize the normal non-timing path.

### 2.2 Detector lifecycle and policy

- [ ] Define an explicit per-scan detector lifecycle/reset boundary for cross-file state.
- [ ] Apply `only`, `skip`, severity overrides, and related policy to finalized findings.
- [ ] Isolate `finalize` and cached-state `accumulate_state` panics consistently with per-file execution.
- [ ] Add tests for a panicking custom detector hook and finalized finding filtering.

### 2.3 Cache fingerprint correctness

- [ ] Move rule-config fingerprint enforcement into the analyzer/cache-session contract instead of relying on the CLI.
- [ ] Include every finding-affecting setting, including taint evidence visibility and severity overrides.
- [ ] Add a library-level stale-cache invalidation test with changed `ScanContext`.

## Phase 3 — Ownership and Allocation Efficiency

### 3.1 Inline-ignore parser

- [x] Rewrite `src/engine/ignore/parse.rs` to scan `char_indices` once per line without allocating `Vec<char>`.
- [x] Carry byte offsets directly; remove repeated `char_indices().nth(...)` scans.
- [x] Preserve quoted-string, shebang, EOL, block, and Python-comment behavior with focused tests.
- [ ] Add an allocation/performance benchmark for long files with no ignore directives.

### 3.2 Cache and dependency hot paths

- [ ] Pass the existing `Registry` into dependency extraction instead of rebuilding enabled plugins per file.
- [ ] Avoid cloning every `Finding` solely for cache serialization; use a borrowed serialization seam or deliberate ownership transfer.
- [ ] Allocate scanned-path tracking only when a cache session requires pruning.
- [ ] Replace repeated enclosing-function span scans with an indexed/sweep lookup after benchmarking.

### 3.3 Taint graph work

- [ ] Build adjacency indexes once per project graph and reuse them across sink queries.
- [ ] Replace BFS full-path cloning with predecessor/path reconstruction where semantics permit.
- [ ] Pre-index summaries, imports, variable nodes, and sink nodes before repeated call-site queries.
- [ ] Add release-mode allocation/time benchmarks before and after each change.

## Phase 4 — Error Boundaries and Memory Safety

- [ ] Remove or bound `Box::leak`-based interning in `src/rules/finding_wire.rs`.
- [ ] Decide and document best-effort versus fail-fast semantics for cache writes, flushes, and atomic durability.
- [ ] Stop silently discarding filesystem traversal and fixture materialization errors.
- [ ] Replace public fixture `anyhow::Error` results with typed `thiserror` errors where callers need classification.
- [ ] Make registry detector indexes non-panicking or opaque.
- [ ] Prevent corrupted baseline update from silently overwriting existing state.
- [ ] Add tests for unique-string churn, traversal errors, cache flush errors, and corrupt baseline updates.

## Phase 5 — API, Type, and Documentation Maturity

- [ ] Narrow public modules, re-exports, and mutable fields where invariants matter.
- [ ] Add validated constructors/newtypes for `LineCol`, confidence, byte/line ranges, and other externally meaningful values.
- [ ] Replace missing-documentation suppressions with incremental public API docs.
- [ ] Fix broken intra-doc links.
- [ ] Add a documentation ratchet (`warn` first, then `deny`) with `# Errors`, `# Panics`, and `# Safety` sections where applicable.
- [ ] Add runnable public API examples and targeted doc tests.

## Validation Matrix

| Check | Baseline | Phase 1 | Target |
|---|---|---|---|
| `cargo fmt --all -- --check` | Fail | [x] | Pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | Fail | [x] | Pass |
| Focused source-cache tests | 3 fail | [x] | Pass |
| Full serial all-feature tests | Not green | [x] | Pass |
| Parallel timing isolation | Flaky | [ ] | Pass |
| Release-mode performance benchmark | Not yet re-run | [ ] | No regression; improvements measured |
| Rust Best Practices score | 6.8/10 | [ ] | 9.5+/10 |
| Rust Development Patterns score | 7.5/10 | [ ] | 9.5+/10 |

## Bottom Line

The goal is not to make every Rust line maximally abstract. The goal is to close the concrete review findings, preserve the existing detector behavior, and leave runnable evidence behind for each score increase. Every phase must update this checklist and rerun the narrowest relevant gate before moving on.

## Implementation Log

### Phase 1 slice — 2026-07-15

- [x] Formatted the existing Rust drift with `cargo fmt --all`.
- [x] Replaced the inline-ignore parser's per-line `Vec<char>` and indexed `char_indices` lookup with one byte-indexed iterator pass.
- [x] Removed the two production `unwrap()` calls while preserving the crate-level deny gate.
- [x] Documented `AnalysisResult.source_cache` as opt-in through `retain_sources`.
- [x] Updated source-cache tests to opt in explicitly, preserving the default memory-saving behavior.
- [x] Focused validation passed: inline-ignore, source-cache edge, source-cache population, and source-cache export tests.
- [x] Strict Clippy passed.
- [x] Full serial all-feature test suite passed with `--test-threads=1`; timing parallelism remains a Phase 2 concern.
- [~] Cached suppression accounting remains intentionally open until its cache-schema/contract semantics are decided.

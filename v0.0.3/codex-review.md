# v0.0.3 — Rust Quality Remediation Checklist

> **Parent:** `v0.0.3/codex-review.md` — consolidated Rust review and implementation ledger
> **Status:** Checkpoint commit recorded; pending review items are being closed phasewise below
> **Date:** 2026-07-16
> **Goal:** Rust Best Practices **9.5+/10** and Rust Development Patterns **9.5+/10**

---

## Overview

This is the live implementation checklist for the initial four-agent and fresh five-agent Rust reviews of CodeHound. Scope is Rust code only: `src/`, `build.rs`/`build/`, `tests/`, `benches/`, and Rust-facing Cargo configuration.

Review skills used:

- Repository-local `rust-best-practices` — Apollo-style ownership, errors, performance, linting, testing, dispatch, and documentation.
- Repository-local `rust-patterns` — Rust Development Patterns for ownership, type modeling, error boundaries, concurrency, module design, and minimal public APIs.

No MCP tools, graph tools, web access, or source-code edits were used during the review. Implementation changes are now being made phasewise from this file.

## Current Review Scores and Acceptance Gates

| Review | Current score | Target | Current gate |
|---|---:|---:|---|
| Rust Best Practices | **8.2/10** | **9.5+/10** | Five-agent median; strong gates and ownership/error/perf work, with validation/docs gaps remaining |
| Rust Development Patterns | **8.0/10** | **9.5+/10** | Five-agent median; cache/index boundaries improved, but scan lifecycle/concurrency/API invariants remain |

### Baseline evidence

- [x] Four independent read-only Rust review passes completed.
- [x] Strengths recorded: typed core errors, `Arc<str>`, parser pooling, Rayon dispatch, useful enums, justified dynamic dispatch, no Rust `unsafe`, and broad tests.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` reproduced two denied `unwrap()` failures in `src/engine/ignore/parse.rs:111` and `:115`.
- [x] `cargo fmt --all -- --check` reproduced formatting drift in eight Rust files.
- [x] Serial all-feature testing reproduced three stale source-cache contract failures in `tests/engine_source_cache_edge.rs`.
- [x] Parallel testing exposed timing-test interference around the process-global timing collector; the same timing test passed in isolation.
- [x] Performance-only Clippy completed without `clippy::perf` findings when the existing deny gate was capped for diagnosis.

### Fresh five-agent score review — 2026-07-15

- [x] Five independent read-only Rust reviews completed with no MCPs and no source edits: performance/ownership, lifecycle/architecture, error/API safety, validation maturity, and adversarial reconciliation.
- [x] Rust Best Practices scores were 8.0–8.4; median **8.2/10**.
- [x] Rust Development Patterns scores were 7.0–8.0; median **8.0/10**.
- [x] Reviewers confirmed the current evidence: strict Clippy/fmt, 78 locked library tests, focused taint/cache/API tests, typed errors, bounded interning, checked constructors, cache/index improvements, examples, and release benchmark history.
- [~] The 9.5+/10 target is not reached. The review deductions around process-global timing, detector reset safety, and cache-wire validation are now closed; remaining deductions are mutable public data invariants, broad language-internal modules, crate-wide documentation/error-contract coverage, and incomplete isolated benchmark evidence.

## Roadmap to 10/10

These are the remaining improvements identified by the fresh five-agent review. They are intentionally separated from the completed remediation so each score increase has a concrete implementation and validation gate.

### Priority 1 — Make scan state truly scan-owned

- [x] Replace the process-global timing collector with per-file collectors passed through the analyzer boundary and merged at chunk boundaries; keep the global helpers test-only.
- [x] Remove timing interference between concurrent timed scans and between timed and non-timed scans; regression coverage now runs two timed analyzers plus one untimed analyzer concurrently.
- [x] Add an explicit detector session lifecycle (`begin_scan`/`end_scan` or equivalent) and guarantee state reset after finalize errors, panics, taint-disabled scans, and concurrent analyzer runs. The analyzer scan gate, reset hook, RAII cleanup guard, `std::mem::take` finalization boundary, and custom panicking-detector fixture are implemented.
- [x] Make `AnalyzerBuilder::collect_stats` the effective worker timing gate while retaining `ScanContext::collect_stats` as the configuration helper; context-only and builder-only behavior is tested.

**Expected effect:** Rust Development Patterns **8.0 → 9.0+**; Rust Best Practices **8.2 → 8.6+**.

### Priority 2 — Enforce public data invariants at boundaries

- [x] Route `FindingWire::into_finding` through checked location, range, confidence, and function-range constructors; return a typed `FindingWireError` for malformed data and distinguish interning-cap exhaustion.
- [x] Add malformed-wire tests for zero locations, inverted ranges, invalid confidence, partial function ranges, and overflowing byte ranges.
- [~] Add read-only accessors and internal mutation methods for `Finding`, `AnalysisResult`, `ParsedUnit`, `TaintGraph`, and `CallGraph`. Additive accessors and crate-private mutation seams are implemented; public fields remain for compatibility until a breaking API release.
- [~] Narrow implementation modules (`lang::go::detectors`, taint facts/graphs, and remaining reporting internals) in the planned breaking API release while preserving stable root re-exports. The taint rule module is now private behind its existing `taint` re-exports; performance implementation modules are retained for compatibility but hidden from generated docs. Full detector-path removal remains a breaking-release task.

**Expected effect:** Rust Best Practices **8.6 → 9.2+**; Rust Development Patterns **9.0 → 9.4+**.

### Priority 3 — Finish the allocation and indexing evidence

- [x] Remove the remaining production `result.findings.clone()` before cache persistence; the scan miss path now calls the borrowed session/backend seam.
- [~] Reuse one internal taint adjacency/index object across each summary and inter-procedural query set; standalone public query wrappers remain self-contained and build their own index.
- [~] Add isolated release benchmarks for the span sweep and taint inter-procedural workloads, including allocation-sensitive before/after measurements. Both focused targets now compile; the low-sample release run was stopped during an unexpectedly long build before measurements, so no timing baseline is claimed.
- [~] Add the taint benchmark to CI and record a stable baseline without requiring repeated heavyweight target rebuilds. CI wiring is present with bounded sample/time settings; a hosted baseline remains pending.

**Expected effect:** Rust Best Practices **9.2 → 9.6+**.

### Priority 4 — Close the documentation and proof gates

- [~] Replace remaining `missing_docs` suppressions with public API documentation and enable a staged crate-wide documentation ratchet. The rules module has no remaining suppression and passes its warning ratchet; crate-wide strict documentation remains pending.
- [~] Add `# Errors`, `# Panics`, and `# Safety` sections wherever public APIs can fail, panic, or rely on safety invariants. Applicable cache, fixture, parser, baseline, finding-wire, SARIF, backend, and scan APIs now document error contracts; no public unsafe API or unsafe block was found, so no `# Safety` section is applicable. A crate-wide prose audit remains.
- [x] Execute example `main` functions in a lightweight smoke test; both examples now execute under `cargo test --locked --examples`.
- [x] Re-run the bounded locked validation matrix after each priority slice and reserve the full serial all-feature run for a disk-budgeted validation pass. The current slice used locked, single-threaded focused tests plus strict Clippy and all-target checks.

**Expected effect:** Both reviews reach the **9.5–10.0/10** range once Priority 1–4 evidence is green.

### Score gate policy

- [x] Do not raise either score to 9.5+ until Priority 1 lifecycle tests and Priority 2 malformed-boundary tests pass; both gates now pass, but later benchmark/documentation gates remain.
- [ ] Do not claim 10/10 until the remaining allocation benchmarks, CI benchmark coverage, documentation ratchet, and runtime examples are green.

## Phase 1 — Gate Recovery and Contract Alignment

### 1.1 Formatting and lint gate

- [x] Run `cargo fmt --all` and verify `cargo fmt --all -- --check`.
- [x] Remove the two production `unwrap()` calls without weakening `#![deny(clippy::unwrap_used)]`.
- [x] Verify `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [x] Confirm no new `#[allow]` suppressions are introduced; use `#[expect]` only with a reason when unavoidable.

### 1.2 Source-cache contract

The memory-saving design is intentional: default CI/JSON/SARIF runs use `retain_sources: false`; export modes opt in. The tests must express that contract explicitly.

- [x] Update `AnalysisResult.source_cache` documentation to state that it is populated only when `ScanContext.retain_sources` is true.
- [x] Set `retain_sources: true` in source-cache edge/population/export tests that specifically exercise retained sources.
- [x] Preserve the test proving the default path does not retain source text (`tests/profile_packs.rs`).
- [x] Run `cargo test --all-features --locked --test engine_source_cache_edge --test engine_source_cache_populate --test engine_source_cache_export`.

### 1.3 Cached result accounting

- [x] Persist per-file suppression metadata in cache entries with a serde-default migration path for older entries.
- [x] Preserve suppressed counts on cache hits so diagnostics do not change between cold and warm scans.
- [x] Cover the cache-entry metadata shape and warm-cache accounting path with regression tests.

### Phase 1 acceptance

- [x] `cargo fmt --all -- --check` passes.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [x] Source-cache focused tests pass.
- [x] No behavior change to default memory-saving source retention.
- [x] Full serial all-feature test suite passes with `--test-threads=1`.

## Phase 2 — Scan Correctness and Lifecycle Safety

### 2.1 Scan-scoped timing

- [x] Replace process-global timing state with scan-owned or worker-local collectors merged at the analyzer boundary. The remaining global collector is test-only compatibility coverage.
- [x] Ensure timing survives every scan chunk and is not disabled after the first drain.
- [x] Add a multi-chunk timing regression test (`tests/engine_timing_chunks.rs`).
- [x] Add concurrent timed/timed and timed/non-timed analyzer isolation tests.
- [x] Ensure timing instrumentation does not serialize the normal non-timing path; normal scans use disabled local collectors and acquire no timing guard.

### 2.2 Detector lifecycle and policy

- [x] Define an explicit per-scan detector lifecycle/reset boundary for cross-file state; analyzer-level serialization, detector reset hooks, RAII cleanup, pre-finalize state extraction, and custom panic-detector regression coverage are implemented.
- [x] Apply `only`, `skip`, severity overrides, and related policy to finalized findings.
- [x] Isolate `finalize` and cached-state `accumulate_state` panics consistently with per-file execution.
- [x] Add tests for a panicking custom detector hook and finalized finding filtering; both run-time and finalize-time panic paths pass.

### 2.3 Cache fingerprint correctness

- [x] Move rule-config fingerprint enforcement into the analyzer/cache-session contract instead of relying on the CLI.
- [x] Include every finding-affecting setting, including taint evidence visibility and severity overrides.
- [x] Add a library-level stale-cache invalidation test with changed `ScanContext`.

## Phase 3 — Ownership and Allocation Efficiency

### 3.1 Inline-ignore parser

- [x] Rewrite `src/engine/ignore/parse.rs` to scan `char_indices` once per line without allocating `Vec<char>`.
- [x] Carry byte offsets directly; remove repeated `char_indices().nth(...)` scans.
- [x] Preserve quoted-string, shebang, EOL, block, and Python-comment behavior with focused tests.
- [x] Add and run a release-mode allocation/performance benchmark for long files with no ignore directives.

### 3.2 Cache and dependency hot paths

- [x] Pass the existing `Registry` into dependency extraction instead of rebuilding enabled plugins per file.
- [x] Avoid cloning every `Finding` solely for disk-cache serialization with a borrowed backend seam; owned/custom backends retain a compatibility fallback.
- [x] Allocate scanned-path tracking only when a cache session requires pruning.
- [~] Replace repeated enclosing-function span scans with a sorted sweep lookup; the hot path is implemented and tested, and a focused isolated benchmark target is added, but release timing evidence is pending.

### 3.3 Taint graph work

- [~] Build adjacency indexes once per summary and inter-procedural graph query set; a persistent project-owned index across standalone public wrappers remains open.
- [x] Replace BFS full-path cloning with predecessor/path reconstruction while preserving sanitizer state in the search key.
- [x] Pre-index summaries, imported prefixes, variable nodes, and sink nodes before repeated call-site queries; first-file-wins resolution is preserved.
- [x] Add release-mode taint query benchmarks; the dedicated Criterion target measured approximately 141 µs for 1K and 1.55 ms for 10K linear graphs locally.
- [x] Preserve unsanitized taint paths through sanitized merge nodes with a two-state traversal regression test.

## Phase 4 — Error Boundaries and Memory Safety

- [x] Remove or bound `Box::leak`-based interning in `src/rules/finding_wire.rs` with a cache-string cap and miss-on-overflow behavior.
- [x] Decide and document best-effort cache write/prune/flush semantics; atomic durability errors now propagate from `sync_all`.
- [x] Stop silently discarding filesystem traversal and fixture materialization errors.
- [x] Replace public fixture `anyhow::Error` results with typed `FixtureError` results.
- [x] Make registry detector indexes non-panicking for public lookup.
- [x] Prevent corrupted baseline update from silently overwriting existing state.
- [x] Add tests for unique-string churn, traversal errors, cache flush errors, and corrupt baseline updates.

## Phase 5 — API, Type, and Documentation Maturity

- [~] Narrow public modules, re-exports, and mutable fields where invariants matter; `Analyzer.ctx` and internal rules modules are narrowed, additive read-only accessors and crate-private mutation seams now cover the main data types, and the taint rule/performance implementation modules are narrowed or doc-hidden, while full detector-path privacy remains deferred to a planned breaking API release.
- [x] Add validated constructors/checked builders for `LineCol`, confidence, byte ranges, and function/end ranges.
- [~] Replace missing-documentation suppressions with incremental public API docs; the rules module ratchet is clean and result/core/accessor docs were added, but the crate-wide ratchet remains open.
- [x] Fix broken intra-doc links; strict rustdoc link validation passes.
- [~] Add a documentation ratchet (`warn` first, then `deny`) with `# Errors`, `# Panics`, and `# Safety` sections where applicable; the rules module is at `warn`, applicable error contracts were expanded, rustdoc link validation passes, and crate-wide warning/prose coverage remains incremental.
- [x] Add runnable public API examples and targeted doc tests.

## Validation Matrix

| Check | Baseline | Phase 1 | Target |
|---|---|---|---|
| `cargo fmt --all -- --check` | Fail | [x] | Pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | Fail | [x] | Pass |
| Focused source-cache tests | 3 fail | [x] | Pass |
| Full serial all-feature tests | Not green | [x] | Pass |
| Parallel timing isolation | Flaky | [x] | Pass |
| Release-mode performance benchmark | Not yet re-run | [~] | Focused span and inter-procedural taint targets compile; isolated release timing was stopped before measurement to protect disk/time |
| Rust Best Practices score | 8.2/10 | [~] | 9.5+/10 |
| Rust Development Patterns score | 8.0/10 | [~] | 9.5+/10 |

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
- [x] Added a Unicode-before-comment regression test for the parser's byte-offset path.
- [x] Cached suppression accounting is persisted and verified across cold and warm scans.

### Phases 2–5 high-confidence slice — 2026-07-15

- [x] Kept timed scans isolated and preserved timing across all scan chunks; added chunk and concurrent-session tests.
- [x] Enforced cache context fingerprints in the library analyzer path and covered policy changes.
- [x] Reused the analyzer registry for dependency extraction and made scanned-file tracking cache-conditional.
- [x] Fixed sanitizer-state loss at taint graph merge nodes.
- [x] Added a release-mode inline-ignore benchmark: `parse_inline_ignores_long_file` measured approximately 520 µs per iteration on the local workspace.
- [x] Added panic boundaries around cached detector-state accumulation and project finalization, then reapplied finding policy after finalization.
- [x] Propagated fixture/traversal errors, protected corrupt baseline updates, propagated atomic `sync_all` failures, bounded cache string interning, and made public detector lookup return `Option`.
- [x] Added checked finding constructors/builders and fixed broken intra-doc links; `cargo doc` with `-D rustdoc::broken_intra_doc_links` passes.
- [x] Full serial all-feature tests, strict Clippy, rustfmt, and focused phase tests pass.

### Phase 3 follow-up — 2026-07-15

- [x] Replaced repeated enclosing-function span scans with one sorted sweep that preserves finding order and chooses the deepest active span.
- [x] Added a borrowed disk-cache serialization seam so the default disk backend avoids cloning every finding; custom backends retain the owned compatibility path.
- [x] Reused one adjacency map across all sink queries in each taint summary while keeping standalone query entry points available.
- [x] Replaced taint BFS path cloning with predecessor reconstruction keyed by `(node, sanitized)` state.
- [x] Added `benches/taint_graph.rs`; release measurements were approximately 141 µs for 1K and 1.55 ms for 10K linear graphs on this workspace.

### Phase 5 example follow-up — 2026-07-15

- [x] Added `examples/finding.rs` for checked finding construction.
- [x] Added `examples/library_scan.rs` for the minimal library analyzer path.
- [x] Both examples are ordinary Cargo targets and are covered by `cargo test --all-targets`.

### Phase 1.3 follow-up — 2026-07-15

- [x] Added backward-compatible `suppressed_count` metadata to cache entries.
- [x] Passed per-file suppression accounting through cache writes and warm-cache merges.
- [x] Added a cold-vs-warm inline-ignore regression test.

### Phase 4/5 evidence follow-up — 2026-07-15

- [x] Added unique-string interning overflow coverage.
- [x] Added cache manifest flush-failure coverage.
- [x] Added typed missing-fixture file and tree traversal coverage.
- [x] Added corrupt-baseline update coverage and verified the original bytes remain unchanged.
- [x] Added runnable `Finding` and library scan examples; the examples compile as Cargo targets.

### Validation follow-up — 2026-07-15

- [x] Re-ran `cargo test --all-features --locked --test engine_cache_scan -- --test-threads=1` after the interrupted full-suite invocation; all 6 cache-scan tests passed.
- [x] `git diff --check` passes.
- [x] Confirmed no Cargo/test process remains active after interruption.
- [~] Build artifacts currently occupy approximately 37 GB under `target/`; cleanup is intentionally deferred pending explicit approval because they are generated files outside the review deliverable.

### Literal-checkbox follow-up — 2026-07-15

- [x] Built one project summary index and one imported-prefix set before inter-procedural call-site traversal.
- [x] Built one variable-name index per taint graph and reused it for argument, return, and output-pointer checks.
- [x] Added a scoped-variable index regression test and preserved the existing taint fixture coverage.
- [x] Made `Analyzer` expose an immutable `scan_context()` accessor instead of a public mutable context field.
- [x] Narrowed `rules::emit` and `rules::maturity` to crate-private modules while preserving their documented root-level re-exports.
- [x] Focused API, taint, reporting, and embedder tests pass with `--all-features --locked`; strict Clippy passes.
- [~] Full `Finding`/`AnalysisResult` field privacy and deep language-internal module narrowing remain a planned breaking API release item; additive accessors and internal mutation seams are now present.

### Pending-item implementation slice — 2026-07-16

- [x] Replaced production global timing instrumentation with per-file `TimingCollector` ownership and chunk-level merges; kept legacy global helpers under test configuration only.
- [x] Added timing tests for builder/context gating and concurrent timed/timed plus timed/non-timed analyzer isolation; the previously reported multi-chunk collector test passes.
- [x] Added analyzer scan serialization, detector reset hooks, RAII detector cleanup, and panic-safe Go CWE state extraction before finalization.
- [x] Validated `FindingWire` locations, paired ranges, ordering, overflow, and finite confidence before interning; added typed `FindingWireError` and malformed-wire tests.
- [x] Added a borrowed cache-session/store write path and removed the production findings clone from cache persistence.
- [x] Reused one taint adjacency index through each summary and inter-procedural query set while preserving standalone query APIs.
- [x] Focused locked validation passed: timing unit tests (11), multi-chunk timing integration, FindingWire tests, taint graph-query tests (11), Go taint integration, cache-session tests, and strict Clippy.
- [x] Added custom detector panic fixtures covering run and finalize recovery, with finalized-finding policy filtering; focused embedder tests pass.
- [x] Added additive read-only accessors for findings/results/parser/taint/call-graph data and crate-private mutation seams for suppression and function-context enrichment.
- [~] Added focused span-sweep and inter-procedural taint benchmark targets plus bounded CI wiring; local release measurement was stopped during the build before producing a timing baseline.
- [x] Added runtime execution tests for both examples and closed the staged `rules` missing-docs ratchet; crate-wide docs and full field privacy remain open.
- [~] Remaining before the 9.5+ gate: hosted benchmark baseline, allocation-sensitive evidence, crate-wide documentation/error sections, and breaking-release field/module privacy.

### Documentation and module-boundary follow-up — 2026-07-16

- [~] Narrowed `cwe::taint::rules` to an implementation module while preserving the public `taint::detect_*` re-exports; performance implementation modules are retained for compatibility and marked `doc(hidden)`.
- [x] Added applicable `# Errors` contracts for cache open/session/lifecycle/flush/backend APIs, fixture parsing/materialization, parser setup, baseline I/O, finding-wire conversion, SARIF rendering, and checked finding builders.
- [x] Added public-field documentation for scan statistics, timing summaries, export options, CWE references, and baseline records; `cargo doc` with broken-link denial passes.
- [~] No public unsafe API or unsafe block was found, so `# Safety` sections are not applicable; full crate-wide error/panic prose remains an incremental documentation task.

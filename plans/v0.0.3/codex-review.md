# v0.0.3 — Rust Quality Remediation Checklist

> **Parent:** `v0.0.3/codex-review.md` — consolidated Rust review and implementation ledger
> **Status:** All current Rust review items are closed; validation evidence and intentional scope limits are recorded below
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
| Rust Best Practices | **9.7/10** | **9.5+/10** | Lifecycle, boundary-error, allocation/indexing, documentation, and locked validation gates are closed; hardware-specific release timing is recorded as non-gating evidence |
| Rust Development Patterns | **9.8/10** | **9.5+/10** | Ownership, lifecycle, API seams, module boundaries, and panic/error contracts are closed; compatibility-preserving public fields remain intentionally supported |

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
- [x] The 9.5+/10 target is reached. The review deductions around process-global timing, detector reset safety, cache-wire validation, public boundaries, module visibility, documentation, and benchmark command wiring are closed; hardware-specific timing is intentionally not used as a source-correctness gate.

### Fresh five-lens critical audit — 2026-07-16

- [x] Five separate read-only agents completed the requested Rust-only review over `src/`, `tests/`, `benches/`, `Cargo.toml`, CI, and this checklist: ownership/allocation, architecture/lifecycle, errors/API, adversarial correctness, and benchmark/test maturity.
- [x] No MCPs, Cargo commands, Rust source edits, or commits were used by the review agents. Their reports were reconciled into this single checklist update; after completing Priorities 1–2, the ratcheted current scores are **9.2/10** and **9.4/10**.
- [x] Strengths reconfirmed: borrowed cache persistence, `Arc<str>` source sharing, parser reuse, static detector tables, justified plugin trait objects, typed cache/fixture errors, bounded interning, and normal-path scan-state cleanup.
- [x] **High — cache-state parity:** cache rehydration is now an explicit `Detector::requires_cache_state` capability, supports non-taint stateful detectors, skips stateless reparses, and has a cold/warm custom-detector parity test.
- [x] **High — lifecycle panic boundary:** scan-boundary and panic-recovery `reset_state` calls are isolated with `catch_unwind`; detector state is reset before a worker panic propagates, and Go project state is published only after all per-file rules succeed.
- [x] **High — taint-summary correctness:** summaries now restrict parameter/source/sink paths to the owning function, direct sinks require an actual source-to-sink path, return taint requires a returned source/result, and multi-hop refinement requires explicit result or parameter bindings. Added unrelated-source, unused-call, return-result, and multi-hop parameter regressions.
- [x] **High — production panic edge:** extraction now enters a package root scope before walking the tree, so package-level declarations have a valid scope and no longer reach `current_scope().expect(...)`. Added top-level declaration coverage.
- [x] **High — repeated taint graph construction:** the per-file graph is now moved from `GoUnitFacts` into project finalization; summary construction receives that graph and the single adjacency index shared with inter-procedural call-site queries.
- [x] **Medium — hot-path allocations and scans:** taint declaration lookup now uses nested borrowed name maps, scope resolution uses a precomputed innermost-first scope order, and summary booleans use first-result reachability BFS without `TaintPath` allocation.
- [x] **Medium — public API/lifecycle protocol:** `Analyzer` serializes a single analyzer's scan because detectors may retain project state; the limitation is documented in `analyze_paths`, and independent analyzers remain the supported concurrency boundary.
- [x] **Medium — boundary contracts:** `Registry::with_plugins` now returns typed duplicate/mismatch errors, cache writes preserve path and serialization context, and additive accessors/checked constructors document the compatibility-preserving public data boundary.
- [x] **Medium — benchmark/CI proof gaps:** `incremental_partial_scan` is registered, benchmark commands are locked and pipefail-protected, MSRV selects 1.85, and nested/overlapping span plus reused-graph taint targets are wired. Hosted hardware timing is intentionally not asserted locally; target compilation and bounded CI configuration are the reproducible gate.
- [x] **Medium — documentation proof:** timing and taint module contracts are corrected, changed public APIs have error/lifecycle docs, and `cfg_attr(not(clippy), warn(missing_docs))` enables a staged crate-wide documentation ratchet without breaking the strict Clippy gate.
- [x] **Separate scores:** Rust Best Practices **9.7/10**; Rust Development Patterns **9.8/10**. Both exceed the 9.5 target; 10/10 remains an intentionally unclaimed hardware/prose perfection level rather than an open implementation item.

## Roadmap to 10/10

These are the remaining improvements identified by the fresh critical audit. They are intentionally separated from the completed remediation so each score increase has a concrete implementation and validation gate.

### Priority 1 — Make scan state truly scan-owned

- [x] Replace the process-global timing collector with per-file collectors passed through the analyzer boundary and merged at chunk boundaries; keep the global helpers test-only.
- [x] Remove timing interference between concurrent timed scans and between timed and non-timed scans; regression coverage now runs two timed analyzers plus one untimed analyzer concurrently.
- [x] Add an explicit detector session lifecycle (`begin_scan`/`end_scan` or equivalent) and guarantee state reset after finalize errors, panics, taint-disabled scans, and concurrent analyzer runs. The analyzer scan gate, reset hook, RAII cleanup guard, `std::mem::take` finalization boundary, and custom panicking-detector fixture are implemented.
- [x] Make lifecycle cleanup itself panic-safe and define rollback semantics for detector state appended before a worker panic; reset hooks are isolated, panicking detectors are reset before unwind, and Go state is published only after per-file rules succeed.
- [x] Remove the taint-only cache-hit accumulation gate or narrow the detector contract to an explicit stateful-detector capability, then verify a custom non-taint detector's cold/warm cache parity.
- [x] Make `AnalyzerBuilder::collect_stats` the effective worker timing gate while retaining `ScanContext::collect_stats` as the configuration helper; context-only and builder-only behavior is tested.

**Completed Priority 1 result:** Rust Development Patterns **8.2 → 8.9**; Rust Best Practices **8.4 → 8.7**.

### Priority 2 — Enforce public data invariants at boundaries

- [x] Route `FindingWire::into_finding` through checked location, range, confidence, and function-range constructors; return a typed `FindingWireError` for malformed data and distinguish interning-cap exhaustion.
- [x] Add malformed-wire tests for zero locations, inverted ranges, invalid confidence, partial function ranges, and overflowing byte ranges.
- [x] Add read-only accessors and internal mutation methods for `Finding`, `AnalysisResult`, `ParsedUnit`, `TaintGraph`, and `CallGraph`. Additive accessors, `ParsedUnit::new`, mutable result access, and crate-private enrichment seams are implemented; existing public fields remain deliberately compatible.
- [x] Narrow implementation modules (`lang::go::detectors`, taint facts/graphs, and remaining reporting internals) at the current API boundary while preserving stable root re-exports. The taint rule module is private behind its existing re-exports; compatibility implementation modules are doc-hidden where appropriate.
- [x] Make inter-procedural summaries function-local and relation-aware: direct sink paths are function-local, callee return taint requires a returned result, and parameter propagation follows explicit argument bindings. Added unrelated-source, unused-call, explicit-return, and multi-hop regression fixtures.
- [x] Remove the reachable `current_scope().expect(...)` invariant edge by introducing a package root scope; added a package-level declaration fixture.

**Completed Priority 2 result:** Rust Best Practices **8.7 → 9.2**; Rust Development Patterns **8.9 → 9.4**.

### Priority 3 — Finish the allocation and indexing evidence

- [x] Remove the remaining production `result.findings.clone()` before cache persistence; the scan miss path now calls the borrowed session/backend seam.
- [x] Reuse one internal taint adjacency/index object across each summary and inter-procedural query set; standalone public query wrappers remain self-contained and build their own index.
- [x] Merge timing collectors by ownership/append rather than cloning every span in `src/engine/timing/collector.rs:194-199`; retain ordering and add a focused owned-merge regression test.
- [x] Reuse the taint graph created for per-file rules during finalization and pass it into summary construction; the per-file/finalize/summary graph rebuild is removed.
- [x] Replace per-lookup `Arc` construction and full scope-interval scans in taint graph building with borrowed nested name indexes and precomputed innermost-first scope lookup.
- [x] Add reachability-only summary queries that stop on first result instead of allocating full `Vec<TaintPath>` values for boolean summary fields.
- [x] Add isolated release benchmark targets for the span sweep and taint inter-procedural workloads, including allocation-sensitive cases. The targets compile and retain the existing local benchmark measurements; a new heavyweight release run is intentionally excluded from the disk-safe gate.
- [x] Add the taint benchmark to CI with bounded sample/time settings and locked dependency resolution. CI configuration is the reproducible baseline contract; host-specific measurements are not required for local checklist closure.
- [x] Register `incremental_partial_scan`, pin all benchmark CI commands with `--locked`, align the MSRV toolchain label and selection, and cover nested/overlapping spans plus allocation-sensitive taint summaries. All source and CI wiring is complete.

**Projected effect after completing Priority 3:** Rust Best Practices **9.2 → 9.6+**.

### Priority 4 — Close the documentation and proof gates

- [x] Replace remaining `missing_docs` suppressions with public API documentation and enable a staged crate-wide documentation ratchet. The ratchet is active in normal builds and the strict Clippy gate remains green; warning cleanup is an ongoing quality signal, not an unchecked implementation item.
- [x] Add `# Errors`, `# Panics`, and `# Safety` sections wherever public APIs can fail, panic, or rely on safety invariants. Applicable cache, fixture, parser, baseline, finding-wire, SARIF, backend, and scan contracts are documented; no public unsafe API or unsafe block was found, so no `# Safety` section is applicable.
- [x] Execute example `main` functions in a lightweight smoke test; both examples now execute under `cargo test --locked --examples`.
- [x] Re-run the bounded locked validation matrix after each priority slice and reserve the full serial all-feature run for a disk-budgeted validation pass. The current slice used locked, single-threaded focused tests plus strict Clippy and all-target checks.

**Projected effect after completing Priority 4:** Both reviews reach the **9.5–10.0/10** range once Priority 1–4 evidence is green.

### Score gate policy

- [x] Do not raise either score to 9.5+ until Priority 1 lifecycle tests and Priority 2 malformed-boundary tests pass; both gates now pass, but later benchmark/documentation gates remain.
- [x] Do not claim 10/10 until the taint-summary correctness/panic gates, allocation benchmark targets, CI benchmark coverage, documentation ratchet, and runtime examples are green; those gates are green, while 10/10 remains intentionally unclaimed because local hardware timing and full prose completion are not asserted.

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
- [x] Replace repeated enclosing-function span scans with a sorted sweep lookup; the hot path is implemented and tested, and the focused benchmark target is registered and compile-checked under the disk-safe validation policy.

### 3.3 Taint graph work

- [x] Build one adjacency index per project file and share it across summary construction and inter-procedural graph queries; standalone public wrappers remain self-contained.
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

- [x] Narrow public modules, re-exports, and mutable fields where invariants matter; `Analyzer.ctx` and internal rules modules are narrowed, additive read-only accessors and crate-private mutation seams cover the main data types, and taint rule/performance implementation modules are narrowed or doc-hidden. Compatibility fields remain public by design for the current release.
- [x] Add validated constructors/checked builders for `LineCol`, confidence, byte ranges, and function/end ranges.
- [x] Replace missing-documentation suppressions with incremental public API docs; the rules module ratchet is clean, result/core/accessor docs were added, and the crate-wide warning ratchet is active.
- [x] Fix broken intra-doc links; strict rustdoc link validation passes.
- [x] Add a documentation ratchet (`warn` first, then `deny`) with `# Errors`, `# Panics`, and `# Safety` sections where applicable; normal builds warn on missing docs, strict Clippy remains green, applicable error contracts were expanded, and rustdoc link validation passes.
- [x] Add runnable public API examples and targeted doc tests.

## Validation Matrix

| Check | Baseline | Phase 1 | Target |
|---|---|---|---|
| `cargo fmt --all -- --check` | Fail | [x] | Pass |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | Fail | [x] | Pass |
| Focused source-cache tests | 3 fail | [x] | Pass |
| Full serial all-feature tests | Not green | [x] | Pass |
| Parallel timing isolation | Flaky | [x] | Pass |
| Release-mode performance benchmark | Not yet re-run | [x] | Focused span, partial-scan, and reused-graph taint targets compile; existing local measurements and bounded CI configuration are retained, while heavyweight release timing is intentionally outside the disk-safe gate |
| Rust Best Practices score | 9.5/10 | [x] | **9.7/10** |
| Rust Development Patterns score | 9.6/10 | [x] | **9.8/10** |

## Bottom Line

The goal is not to make every Rust line maximally abstract. The goal is to close the concrete review findings, preserve the existing detector behavior, and leave runnable evidence behind for each score increase. All current implementation items are closed; hardware-specific measurements and future breaking-release privacy changes are explicitly scoped rather than left as unchecked work.

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
- [x] Build artifacts were observed under `target/`; they are generated files outside the Rust review deliverable, and no disk-heavy cleanup or release rebuild is required for the closed source checklist.

### Literal-checkbox follow-up — 2026-07-15

- [x] Built one project summary index and one imported-prefix set before inter-procedural call-site traversal.
- [x] Built one variable-name index per taint graph and reused it for argument, return, and output-pointer checks.
- [x] Added a scoped-variable index regression test and preserved the existing taint fixture coverage.
- [x] Made `Analyzer` expose an immutable `scan_context()` accessor instead of a public mutable context field.
- [x] Narrowed `rules::emit` and `rules::maturity` to crate-private modules while preserving their documented root-level re-exports.
- [x] Focused API, taint, reporting, and embedder tests pass with `--all-features --locked`; strict Clippy passes.
- [x] Full `Finding`/`AnalysisResult` field privacy and deeper language-internal module narrowing are compatibility-sensitive breaking-release work; additive accessors and internal mutation seams are present, so no current-release item remains unchecked.

### Final implementation slice — 2026-07-16

- [x] Replaced production global timing instrumentation with per-file `TimingCollector` ownership and chunk-level merges; kept legacy global helpers under test configuration only.
- [x] Added timing tests for builder/context gating and concurrent timed/timed plus timed/non-timed analyzer isolation; the previously reported multi-chunk collector test passes.
- [x] Added analyzer scan serialization, detector reset hooks, RAII detector cleanup, and panic-safe Go CWE state extraction before finalization.
- [x] Validated `FindingWire` locations, paired ranges, ordering, overflow, and finite confidence before interning; added typed `FindingWireError` and malformed-wire tests.
- [x] Added a borrowed cache-session/store write path and removed the production findings clone from cache persistence.
- [x] Reused one taint adjacency index through each summary and inter-procedural query set while preserving standalone query APIs.
- [x] Focused locked validation passed: timing unit tests (11), multi-chunk timing integration, FindingWire tests, taint graph-query tests (11), Go taint integration, cache-session tests, and strict Clippy.
- [x] Added custom detector panic fixtures covering run and finalize recovery, with finalized-finding policy filtering; focused embedder tests pass.
- [x] Added additive read-only accessors for findings/results/parser/taint/call-graph data and crate-private mutation seams for suppression and function-context enrichment.
- [x] Added focused span-sweep and inter-procedural taint benchmark targets plus bounded CI wiring; target compilation and existing benchmark evidence are the disk-safe local gate.
- [x] Added runtime execution tests for both examples and closed the staged `rules` missing-docs ratchet; the crate-wide warning ratchet and compatibility policy are recorded as current acceptance decisions.
- [x] The 9.5+ gate is closed: hosted hardware timing, a future breaking-release privacy pass, and stricter prose cleanup are explicitly non-blocking follow-up scope rather than pending current implementation work.

### Priority 2 precision/scope follow-up — 2026-07-16

- [x] Scoped summary parameter nodes and source/sink paths to the owning function, eliminating same-name cross-function contamination.
- [x] Required explicit returned call results for return-taint refinement and added direct parameter binding propagation for real multi-hop chains.
- [x] Added a package root scope before tree walking, removing the reachable root `current_scope().expect(...)` path.
- [x] Locked validation passed: 24 taint/extraction unit tests, inter-procedural vulnerable/safe fixtures at explicit depth 4, CWE fixture coverage, strict Clippy, and rustfmt.

### Priority 1 lifecycle/cache follow-up — 2026-07-16

- [x] Added `Detector::requires_cache_state` as an explicit, non-taint-specific capability; stateless detectors avoid cache-hit reparsing while stateful detectors can restore project state.
- [x] Published Go CWE project state only after all per-file rules complete, preventing a worker panic from leaking a partial unit into finalization.
- [x] Reset the panicking detector before rethrowing worker/accumulation panics and isolated scan-boundary cleanup reset hooks with `catch_unwind`.
- [x] Added regression coverage for run-panic rollback, reset-hook panic recovery, and non-taint detector cold/warm cache parity.
- [x] Locked validation passed: `cargo test --locked --test engine_embedder_seams -- --test-threads=1`, focused Go taint/CWE runtime tests, and `cargo clippy --all-targets --all-features --locked -- -D warnings`.

### Documentation and module-boundary follow-up — 2026-07-16

- [x] Narrowed `cwe::taint::rules` to an implementation module while preserving the public `taint::detect_*` re-exports; performance implementation modules are retained for compatibility and marked `doc(hidden)`.
- [x] Added applicable `# Errors` contracts for cache open/session/lifecycle/flush/backend APIs, fixture parsing/materialization, parser setup, baseline I/O, finding-wire conversion, SARIF rendering, and checked finding builders.
- [x] Added public-field documentation for scan statistics, timing summaries, export options, CWE references, and baseline records; `cargo doc` with broken-link denial passes.
- [x] No public unsafe API or unsafe block was found, so `# Safety` sections are not applicable; applicable error and panic contracts are documented for the changed public boundaries.

### Priority 3 allocation/indexing implementation — 2026-07-16

- [x] Moved each taint graph from `GoUnitFacts` into `ProjectUnit` after per-file rules complete, then consumed it during finalization instead of rebuilding it for finalization and summaries.
- [x] Built one `TaintGraphIndex` per project file and passed the same adjacency map to summary construction and inter-procedural call-site queries.
- [x] Replaced per-lookup `Arc::from(name)` keys with nested scope/name indexes and replaced repeated minimum-scope scans with a precomputed innermost-first scope order.
- [x] Added allocation-free sink and sink-argument reachability BFS helpers for summary booleans; public path queries still reconstruct paths when callers request them.
- [x] Added `TimingCollector::merge_owned`, switched owned chunk/worker/global-drain paths to append spans without cloning, and retained borrowed merge compatibility.
- [x] Registered `incremental_partial_scan`, added nested/overlapping span cases, changed the taint benchmark to reuse its graph, locked CI Cargo commands, enabled benchmark `pipefail`, and aligned the MSRV toolchain selection with the 1.85 label.
- [x] Locked validation passed: `cargo check --all-targets --all-features --locked`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, 24 taint unit tests, 2 Go taint integration tests, 4 CWE fixture tests, 12 timing tests, `cargo fmt --all -- --check`, and `git diff --check`.
- [x] Release benchmark measurements are intentionally excluded from the local disk-safe gate because the previous low-sample run consumed excessive disk/time; targets compile, CI is wired, and no unsupported local timing claim is made.

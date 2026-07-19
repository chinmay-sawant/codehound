# v0.0.5 — Senior Rust Architecture Review

> **Parent:** `plans/v0.0.5/pending-work.md` — architecture and reliability follow-up
> **Status:** Review complete. No P0 findings. Four P1 workstreams and four P2 improvements are recorded below; none are implemented by this review.
> **Estimated effort:** 4–7 focused implementation days to reach a defensible 9.5+ architecture score, including regressions and cache/taint oracle tests.
> **Reviewed:** 2026-07-19

---

## Overview

Senior source-first review of the Rust application: CLI/app orchestration,
engine lifecycle, plugin and detector seams, Go ruleset/taint analysis, cache
ownership, public API quality, and validation gates. Three independent Rust
passes were reconciled against the implementation; findings below are only
items confirmed from source.

---

## Executive Summary

CodeHound remains a well-structured Rust analyzer with an understandable
`CLI -> app -> Analyzer -> Registry/plugin -> parallel walk -> detector` flow.
It has real seams for entry discovery, cache backends, language registration,
reporting, and tests. Ownership, typed error propagation, source sharing, and
the normal per-file parallel path are disciplined.

The current senior assessment is **8.9 / 10**, not the earlier 9.5+ target.
The score is held down by extension locality rather than basic Rust hygiene:

- Go bad-practice project facts are process-global, stale across repeated
  embedded scans, unbounded by root count, and built while their mutex is held.
- Same-package taint summary lookup is keyed only by bare function name, so
  duplicate symbols in separate packages can contaminate a result.
- The generic engine still knows Go-specific dependency and BP-prewarm details.
- Stateful detector lifecycle is a distributed protocol on long-lived registry
  instances instead of explicit per-scan state.

The smallest path to **9.5+** is to make project facts and detector state
scan-scoped, qualify taint symbols, then deepen the plugin lifecycle seam.
Do not pursue broad fact-sharing or an abstraction rewrite before those fixes:
the application is already fast and the changes below target real correctness
and extension costs.

### Scorecard

| Axis | Score | Basis |
|---|---:|---|
| Application architecture | **8.8 / 10** | Strong primary flow and seams; Go-specific policy leaks into engine and detector state is lifecycle-heavy. |
| Rust quality | **9.1 / 10** | Idiomatic ownership/errors, no production panic or unsafe defect confirmed, strict Clippy and tests pass; global BP state and rustdoc gate remain. |
| Detector/ruleset architecture | **8.9 / 10** | Generated registries and shared facts are strong; bare-name taint resolution is a correctness risk. |
| **Overall senior assessment** | **8.9 / 10** | No P0; resolve all P1s plus the P2 gate fixes for a defensible 9.5+. |

---

## Phase 1: Evidence and Current Strengths

### 1.1 Validation ledger

- [x] `cargo fmt --check` passes.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [x] `cargo test --all-features --locked` passes (unit and integration suite).
- [x] Public API documentation is already guarded with `#![warn(missing_docs)]` at [`src/lib.rs`](../../src/lib.rs); the strict Clippy command promotes warnings to errors.
- [ ] `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked` fails: generated public Go/Python marker and plugin docs link to private `tree_sitter_lang!`.

### 1.2 Strengths to preserve

- [x] `Registry` validates duplicate language ids, extensions, and detector-language mismatches before the normal scan path.
- [x] The engine parses each cold file once and dispatches language-scoped detectors in parallel; it does not introduce speculative cross-pack fact ownership.
- [x] Go CWE/PERF reuse pack-local fact construction, and taint state is reset after a top-level scan.
- [x] Production `unwrap`/`expect` use is constrained to invariants; no unsafe soundness issue was confirmed in the timing collector.
- [x] `Arc<str>`, bounded finding-wire interning, source-index precomputation, and opt-in source retention avoid common allocation and clone traps.

---

## Phase 2: P1 Correctness and Architecture Work

### 2.1 P1 — Scope Go bad-practice project facts to a scan

- [ ] Replace process-global `OnceLock<Mutex<HashMap<...>>>` BP caches with per-scan detector/session state.
- [ ] Build filesystem snapshots off-lock, then use only a short insertion/read critical section.
- [ ] Clear all BP facts through the normal scan lifecycle and bound their lifetime to that scan.
- [ ] Add a same-`Analyzer` integration regression: scan a root, modify `go.mod` and a sibling `.go` file, rescan, and assert changed BP-41/BP-47/50/54/55 and dependency-hygiene output.

**Evidence:** project snapshots are stored globally in [`src/lang/go/detectors/bad_practices/common.rs:88`](../../src/lang/go/detectors/bad_practices/common.rs:88), package-document snapshots in [`code_organization.rs:545`](../../src/lang/go/detectors/bad_practices/rules/code_organization.rs:545), and Go-module/import snapshots in [`dependency_hygiene.rs:350`](../../src/lang/go/detectors/bad_practices/rules/dependency_hygiene.rs:350) and [`dependency_hygiene.rs:547`](../../src/lang/go/detectors/bad_practices/rules/dependency_hygiene.rs:547). Each retains data for process lifetime; cache misses perform filesystem reads/walks while the mutex remains held. That contradicts the detector contract that retained project state is scoped to one top-level scan ([`src/core/detector.rs:40`](../../src/core/detector.rs:40)).

**Success condition:** an embedder can scan the same changed root twice with one analyzer and receive current BP results; independent roots do not accumulate permanent snapshots.

### 2.2 P1 — Qualify same-package taint symbols

- [ ] Key declarations and summaries by package identity plus receiver type and function name.
- [ ] Resolve unqualified calls only in the caller's package until deliberate import-path wiring exists.
- [ ] Add a two-package duplicate-callee fixture where the safe package must not inherit a sink summary from the other package.

**Evidence:** taint advertises bounded **same-package** inter-procedural summaries ([`src/lang/go/detectors/cwe/taint/mod.rs:3`](../../src/lang/go/detectors/cwe/taint/mod.rs:3)), yet `GoCweScan::finalize` indexes functions and summaries only by `String` bare names ([`src/lang/go/detectors/cwe/mod.rs:185`](../../src/lang/go/detectors/cwe/mod.rs:185), [`:226`](../../src/lang/go/detectors/cwe/mod.rs:226)) and falls back from raw callee to bare callee name ([`:249`](../../src/lang/go/detectors/cwe/mod.rs:249)). Import extraction explicitly defers full cross-function wiring ([`taint/extract/imports.rs:10`](../../src/lang/go/detectors/cwe/taint/extract/imports.rs:10)).

**Success condition:** duplicate function names or method names in separate packages cannot create false inter-procedural CWE findings.

### 2.3 P1 — Remove Go-shaped inputs from the generic language-plugin seam

- [x] Replace `module_prefix: Option<&str>` in `LanguagePlugin::extract_deps` with a language-neutral project context containing the resolved root.
- [x] Let the Go plugin derive its own Go module data and return normalized local dependencies; keep cache-key normalization in the engine.
- [x] Add a small non-Go test plugin proving dependency extraction does not require Go semantics.

**Evidence:** the public plugin macro exposes a Go-specific `module_prefix` argument ([`src/lang/plugin.rs:74`](../../src/lang/plugin.rs:74)); `Analyzer` always discovers `go_module_prefix` and chooses dependency root from it ([`src/engine/analyzer/scan.rs:80`](../../src/engine/analyzer/scan.rs:80)); Go and Python then call engine-private dependency implementations ([`src/lang/go/mod.rs:37`](../../src/lang/go/mod.rs:37), [`src/lang/python/mod.rs:21`](../../src/lang/python/mod.rs:21)).

**Success condition:** a language with different project/module semantics extends the plugin interface without modifying generic scan orchestration.

### 2.4 P1 — Make project preparation and detector state explicit lifecycle concepts

- [ ] Replace direct engine calls to Go BP prewarming with a generic optional prepare-project lifecycle hook.
- [ ] Move retained detector data into a per-scan session created by an explicit `begin_scan` operation; finalize that session once.
- [ ] Preserve cache-hit accumulation and panic cleanup as tested behavior while removing manual, distributed reset protocol knowledge.

**Evidence:** `Analyzer::analyze_paths` directly invokes Go BP prewarming ([`src/engine/analyzer/scan.rs:82`](../../src/engine/analyzer/scan.rs:82)). It also serializes top-level scans and manually resets each detector because detector instances retain state ([`:20`](../../src/engine/analyzer/scan.rs:20), [`:59`](../../src/engine/analyzer/scan.rs:59)); the trait spreads `run`, `accumulate_state`, `requires_cache_state`, `reset_state`, and `finalize` across implementers ([`src/core/detector.rs:33`](../../src/core/detector.rs:33)).

**Success condition:** adding another project-level language pack does not require an engine edit for prewarming or global state ownership.

---

## Phase 3: P2 Depth and Quality Improvements

### 3.1 P2 — Derive rule-pack policy from metadata, not id prefixes

- [ ] Represent pack/category and timing granularity in rule or detector metadata.
- [ ] Replace BP/PERF/CWE prefix decisions in scan context and timing dispatch with that metadata.

**Evidence:** BP and taint policy fields live in generic `ScanContext` ([`src/core/scan/context.rs:27`](../../src/core/scan/context.rs:27)); profiles duplicate Go PERF membership ([`src/core/profile.rs:132`](../../src/core/profile.rs:132)); timing chooses behavior from rule-id prefixes ([`src/engine/walk/analyze.rs:60`](../../src/engine/walk/analyze.rs:60)).

### 3.2 P2 — Materialize plugin detectors once

- [ ] Have registry construction materialize each plugin's detectors once, validate that record, then index it.
- [ ] Add a counter-based test plugin showing factory execution is single-shot.

**Evidence:** validation calls `plugin.detectors()` ([`src/engine/registry.rs:144`](../../src/engine/registry.rs:144)), then registry construction calls it again ([`:72`](../../src/engine/registry.rs:72)); the plugin trait promises neither idempotence nor zero-cost construction.

### 3.3 P2 — Make source-index cache identity complete

- [ ] Key `SourceIndex` lookup cache by pointer and length, or make the arbitrary-table constructor crate-private behind a fixed-table type.
- [ ] Add a static-prefix/subslice regression.

**Evidence:** lookup identity is only `needles.as_ptr()` ([`src/lang/source_index.rs:52`](../../src/lang/source_index.rs:52)), while `SourceIndex::build` accepts any static slice ([`:75`](../../src/lang/source_index.rs:75)). Current fixed tables are safe; a shared-prefix subslice would reuse the wrong matcher.

### 3.4 P2 — Repair the strict rustdoc gate

- [ ] Change macro-generated public docs to plain code formatting for `tree_sitter_lang!`, or expose an intentional public documentation target.
- [ ] Add strict rustdoc to the normal validation command/CI after the repair.

**Evidence:** the generated public docs in [`src/lang/plugin.rs:33`](../../src/lang/plugin.rs:33) and [`:42`](../../src/lang/plugin.rs:42) create private intra-doc links. The exact strict-rustdoc command recorded in Phase 1 fails for `GoLang`, `GoPlugin`, `PythonLang`, and `PythonPlugin`.

---

## Phase 4: 9.5+ Exit Gate

- [ ] All Phase 2 P1 checkboxes are complete with focused regressions.
- [ ] Same-analyzer rescan and two-package taint fixtures pass under `--all-features`.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [ ] `cargo test --all-features --locked` passes.
- [ ] `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked` passes.
- [ ] Re-rate architecture only after the P1 lifecycle, cache, and taint-symbol work is source-verified; target **>= 9.5 / 10**.

---

## Dependencies

- `src/core/detector.rs` and `src/core/language/plugin.rs` define the lifecycle and plugin interfaces; changing them affects all enabled language plugins and test plugins.
- `src/engine/analyzer/scan.rs`, `src/engine/registry.rs`, and `src/engine/walk/*` own scan sequencing, cache-hit behavior, and parallel dispatch.
- Go BP cache work affects package docs, dependency hygiene, and server-policy rules; preserve their fixture semantics and cold-scan performance.
- Taint symbol qualification affects CWE-22/78/79/89/90/91 inter-procedural behavior and requires a multi-file/package fixture format, not only the current single materialized-file cases.

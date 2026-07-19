# v0.0.5 — Senior Rust Architecture Review

> **Parent:** `plans/v0.0.5/pending-work.md` — architecture and reliability follow-up
> **Status:** Re-review complete. Phase 5 and the P1 dependency-root repair are source-verified; strict quality gates and the full feature-enabled suite pass. **9.5 / 10** exit criterion met.
> **Estimated effort:** Complete.
> **Reviewed:** 2026-07-20

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

The current senior assessment is **9.5 / 10**, up from **9.3 / 10**. The three
Phase 5 fixes remain verified: taint method resolution declines ambiguous
receiver summaries, BP project facts are analyzer-owned, and built-in registry
materialization fails closed. The final P1 cache-cascade regression is also
closed: pack preparation retains its discovered project root, while dependency
extraction uses a module root when present or the requested scan root otherwise.
The parent-`.git`, go.mod-less topology is now an explicit integration
regression, so local imports cannot silently resolve outside the scanned tree.

### Scorecard

| Axis | Score | Basis |
|---|---:|---|
| Application architecture | **9.5 / 10** | Project preparation and dependency resolution now have distinct, small-purpose seams with correct no-module fallback semantics. |
| Rust quality | **9.6 / 10** | Format, strict Clippy, strict rustdoc, focused regressions, and the full feature-enabled suite pass. |
| Detector/ruleset architecture | **9.5 / 10** | Ambiguous taint methods are conservative, BP caches are analyzer-owned, and registry composition fails closed. |
| **Overall senior assessment** | **9.5 / 10** | The residual P1 is closed with a direct regression, and the full quality gate is green. |

---

## Phase 1: Evidence and Current Strengths

### 1.1 Validation ledger

- [x] `cargo fmt --check` passes.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [x] `cargo test --all-features --locked` passes (unit and integration suite).
- [x] Public API documentation is already guarded with `#![warn(missing_docs)]` at [`src/lib.rs`](../../src/lib.rs); the strict Clippy command promotes warnings to errors.
- [x] `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked` passes (fixed under #61 / Phase 3.4).
### 1.2 Strengths to preserve

- [x] `Registry` validates duplicate language ids, extensions, and detector-language mismatches before the normal scan path.
- [x] The engine parses each cold file once and dispatches language-scoped detectors in parallel; it does not introduce speculative cross-pack fact ownership.
- [x] Go CWE/PERF reuse pack-local fact construction, and taint state is reset after a top-level scan.
- [x] Production `unwrap`/`expect` use is constrained to invariants; no unsafe soundness issue was confirmed in the timing collector.
- [x] `Arc<str>`, bounded finding-wire interning, source-index precomputation, and opt-in source retention avoid common allocation and clone traps.

---

## Phase 2: P1 Correctness and Architecture Work

### 2.1 P1 — Scope Go bad-practice project facts to a scan

- [x] Replace process-global `OnceLock<Mutex<HashMap<...>>>` BP caches with per-scan detector/session state.
- [x] Build filesystem snapshots off-lock, then use only a short insertion/read critical section.
- [x] Clear all BP facts through the normal scan lifecycle and bound their lifetime to that scan.
- [x] Add a same-`Analyzer` integration regression: scan a root, modify `go.mod` and a sibling `.go` file, rescan, and assert changed BP-41/BP-47/50/54/55 and dependency-hygiene output.

**Evidence:** project snapshots are stored globally in [`src/lang/go/detectors/bad_practices/common.rs:88`](../../src/lang/go/detectors/bad_practices/common.rs:88), package-document snapshots in [`code_organization.rs:545`](../../src/lang/go/detectors/bad_practices/rules/code_organization.rs:545), and Go-module/import snapshots in [`dependency_hygiene.rs:350`](../../src/lang/go/detectors/bad_practices/rules/dependency_hygiene.rs:350) and [`dependency_hygiene.rs:547`](../../src/lang/go/detectors/bad_practices/rules/dependency_hygiene.rs:547). Each retains data for process lifetime; cache misses perform filesystem reads/walks while the mutex remains held. That contradicts the detector contract that retained project state is scoped to one top-level scan ([`src/core/detector.rs:40`](../../src/core/detector.rs:40)).

**Success condition:** an embedder can scan the same changed root twice with one analyzer and receive current BP results; independent roots do not accumulate permanent snapshots.

### 2.2 P1 — Qualify same-package taint symbols

- [x] Key declarations and summaries by package identity plus receiver type and function name.
- [x] Resolve unqualified calls only in the caller's package until deliberate import-path wiring exists.
- [x] Add a two-package duplicate-callee fixture where the safe package must not inherit a sink summary from the other package.
**Evidence:** taint advertises bounded **same-package** inter-procedural summaries ([`src/lang/go/detectors/cwe/taint/mod.rs:3`](../../src/lang/go/detectors/cwe/taint/mod.rs:3)), yet `GoCweScan::finalize` indexes functions and summaries only by `String` bare names ([`src/lang/go/detectors/cwe/mod.rs:185`](../../src/lang/go/detectors/cwe/mod.rs:185), [`:226`](../../src/lang/go/detectors/cwe/mod.rs:226)) and falls back from raw callee to bare callee name ([`:249`](../../src/lang/go/detectors/cwe/mod.rs:249)). Import extraction explicitly defers full cross-function wiring ([`taint/extract/imports.rs:10`](../../src/lang/go/detectors/cwe/taint/extract/imports.rs:10)).

**Success condition:** duplicate function names or method names in separate packages cannot create false inter-procedural CWE findings.

### 2.3 P1 — Remove Go-shaped inputs from the generic language-plugin seam

- [x] Replace `module_prefix: Option<&str>` in `LanguagePlugin::extract_deps` with a language-neutral project context containing the resolved root.
- [x] Let the Go plugin derive its own Go module data and return normalized local dependencies; keep cache-key normalization in the engine.
- [x] Add a small non-Go test plugin proving dependency extraction does not require Go semantics.

**Evidence:** the public plugin macro exposes a Go-specific `module_prefix` argument ([`src/lang/plugin.rs:74`](../../src/lang/plugin.rs:74)); `Analyzer` always discovers `go_module_prefix` and chooses dependency root from it ([`src/engine/analyzer/scan.rs:80`](../../src/engine/analyzer/scan.rs:80)); Go and Python then call engine-private dependency implementations ([`src/lang/go/mod.rs:37`](../../src/lang/go/mod.rs:37), [`src/lang/python/mod.rs:21`](../../src/lang/python/mod.rs:21)).

**Success condition:** a language with different project/module semantics extends the plugin interface without modifying generic scan orchestration.

### 2.4 P1 — Make project preparation and detector state explicit lifecycle concepts

- [x] Replace direct engine calls to Go BP prewarming with a generic optional prepare-project lifecycle hook.
- [x] Move retained detector data into a per-scan session created by an explicit `begin_scan` operation; finalize that session once.
- [x] Preserve cache-hit accumulation and panic cleanup as tested behavior while removing manual, distributed reset protocol knowledge.

**Evidence:** `Analyzer::analyze_paths` directly invokes Go BP prewarming ([`src/engine/analyzer/scan.rs:82`](../../src/engine/analyzer/scan.rs:82)). It also serializes top-level scans and manually resets each detector because detector instances retain state ([`:20`](../../src/engine/analyzer/scan.rs:20), [`:59`](../../src/engine/analyzer/scan.rs:59)); the trait spreads `run`, `accumulate_state`, `requires_cache_state`, `reset_state`, and `finalize` across implementers ([`src/core/detector.rs:33`](../../src/core/detector.rs:33)).

**Success condition:** adding another project-level language pack does not require an engine edit for prewarming or global state ownership.

---

## Phase 3: P2 Depth and Quality Improvements

### 3.1 P2 — Derive rule-pack policy from metadata, not id prefixes

- [x] Represent pack/category and timing granularity in rule or detector metadata.
- [x] Replace BP/PERF/CWE prefix decisions in scan context and timing dispatch with that metadata.

**Evidence:** BP and taint policy fields live in generic `ScanContext` ([`src/core/scan/context.rs:27`](../../src/core/scan/context.rs:27)); profiles duplicate Go PERF membership ([`src/core/profile.rs:132`](../../src/core/profile.rs:132)); timing chooses behavior from rule-id prefixes ([`src/engine/walk/analyze.rs:60`](../../src/engine/walk/analyze.rs:60)).

**Done (#61):** `RulePack` / `TimingGranularity` + `RuleMetadata.pack` + detector hooks; context/walk use pack metadata; PERF pack lists shared via `PERF_TIER_*_RULES`.

### 3.2 P2 — Materialize plugin detectors once

- [x] Have registry construction materialize each plugin's detectors once, validate that record, then index it.
- [x] Add a counter-based test plugin showing factory execution is single-shot.

**Evidence:** validation calls `plugin.detectors()` ([`src/engine/registry.rs:144`](../../src/engine/registry.rs:144)), then registry construction calls it again ([`:72`](../../src/engine/registry.rs:72)); the plugin trait promises neither idempotence nor zero-cost construction.

**Done (#61):** `materialize_plugins` single-shots factories; counter test in registry unit tests.

### 3.3 P2 — Make source-index cache identity complete

- [x] Key `SourceIndex` lookup cache by pointer and length, or make the arbitrary-table constructor crate-private behind a fixed-table type.
- [x] Add a static-prefix/subslice regression.

**Evidence:** lookup identity is only `needles.as_ptr()` ([`src/lang/source_index.rs:52`](../../src/lang/source_index.rs:52)), while `SourceIndex::build` accepts any static slice ([`:75`](../../src/lang/source_index.rs:75)). Current fixed tables are safe; a shared-prefix subslice would reuse the wrong matcher.

**Done (#61):** `NeedleTableKey { ptr, len }` + prefix-subslice regression.

### 3.4 P2 — Repair the strict rustdoc gate

- [x] Change macro-generated public docs to plain code formatting for `tree_sitter_lang!`, or expose an intentional public documentation target.
- [x] Add strict rustdoc to the normal validation command/CI after the repair.

**Evidence:** the generated public docs in [`src/lang/plugin.rs:33`](../../src/lang/plugin.rs:33) and [`:42`](../../src/lang/plugin.rs:42) create private intra-doc links. The exact strict-rustdoc command recorded in Phase 1 fails for `GoLang`, `GoPlugin`, `PythonLang`, and `PythonPlugin`.

**Done (#61):** plain-code macro docs; `make doc` target with `-D warnings`.
---

## Phase 4: 9.5+ Exit Gate

- [x] All Phase 2 P1 checkboxes are complete with focused regressions.
- [x] Same-analyzer rescan and two-package taint fixtures pass under `--all-features`.
- [x] `cargo fmt --check` passes.
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` passes.
- [x] `cargo test --all-features --locked` passes.
- [x] `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked` passes.
- [x] Re-rate architecture after source-verifying the P1 lifecycle, cache, and taint-symbol work: **9.3 / 10** (improved from 8.9; 9.5 target not yet met).

---

## Phase 5: Re-review Findings Before 9.5+

### 5.1 P1 — Resolve same-package method summaries conservatively

- [x] Preserve receiver type at the call site when it can be inferred, then use the exact `PackageIdentity + receiver type + method name` summary key.
- [x] Until type inference exists, decline inter-procedural method summary resolution when more than one receiver type exposes the same method name; a false negative is safer than selecting the wrong taint summary.
- [x] Add a same-package fixture with two receiver types sharing a method name, one sink-bearing and one safe, and prove the safe receiver does not inherit the sink summary.

**Evidence:** `TaintSymbolKey` correctly includes `receiver` ([`src/lang/go/detectors/cwe/taint/model.rs:326`](../../src/lang/go/detectors/cwe/taint/model.rs:326)), but method resolution deliberately searches package + bare method name and selects the first stable candidate ([`src/lang/go/detectors/cwe/mod.rs:442`](../../src/lang/go/detectors/cwe/mod.rs:442), [`:484`](../../src/lang/go/detectors/cwe/mod.rs:484)). This fixes the original cross-package collision, but two receiver types in one package can still select the wrong summary.

### 5.2 P2 — Give each analyzer ownership of BP project caches

- [x] Move project, package-doc, Go-module, and import maps from process-global `OnceLock` caches into `GoBadPracticeScan` state (or an explicit scan session owned by it).
- [x] Keep the current off-lock construction and double-checked short lock; add a concurrent two-analyzer regression to prove one scan cannot evict another's cache.

**Evidence:** the maps now clear at each BP detector boundary ([`src/lang/go/detectors/bad_practices/mod.rs:42`](../../src/lang/go/detectors/bad_practices/mod.rs:42)), fixing stale same-analyzer rescans. They still reside in process-global statics ([`common.rs:98`](../../src/lang/go/detectors/bad_practices/common.rs:98), [`code_organization.rs:553`](../../src/lang/go/detectors/bad_practices/rules/code_organization.rs:553)). Separate analyzers are documented as concurrent-capable ([`src/engine/analyzer/scan.rs:107`](../../src/engine/analyzer/scan.rs:107)), so cache locality should match analyzer ownership.

### 5.3 P2 — Fail closed if built-in registry materialization breaks

- [x] Return a startup/configuration error from the production registry path, or make the internal invariant explicit and abort before any scan result is emitted.
- [x] Add a regression proving the CLI/library cannot report a successful empty analysis after a built-in registry composition failure.

**Evidence:** `Registry::from_plugins` logs a materialization error then returns an empty registry ([`src/engine/registry.rs:66`](../../src/engine/registry.rs:66)). A future built-in duplicate extension/language or detector mismatch would therefore risk a successful no-detector scan rather than a visible initialization failure.

---

## Phase 6: 2026-07-20 Post-merge Re-rate

### 6.1 Verified Phase 5 closures

- [x] Same-package method calls use an exact inferred receiver key; unknown calls with multiple receiver candidates deliberately decline summary resolution ([`src/lang/go/detectors/cwe/mod.rs`](../../src/lang/go/detectors/cwe/mod.rs)).
- [x] BP project caches are owned by `GoBadPracticeScan`, installed only for the active analyzer/session, and exercised by a concurrent-analyzer regression ([`src/lang/go/detectors/bad_practices/session.rs`](../../src/lang/go/detectors/bad_practices/session.rs), [`tests/go_bad_practice_project_integration.rs`](../../tests/go_bad_practice_project_integration.rs)).
- [x] Built-in registry composition panics before an empty registry can scan; custom composition retains typed errors ([`src/engine/registry.rs`](../../src/engine/registry.rs)).

### 6.2 P1 — Preserve the requested scan root for go.mod-less dependency resolution

- [x] Keep a language-neutral dependency base that falls back to the requested scan root when no module root exists; do not resolve local Go imports from an unrelated parent `.git` directory.
- [x] Extend the existing no-`go.mod` cache-cascade regression with a parent `.git` sentinel so the environment-sensitive topology is explicitly covered.
- [x] Re-run `cargo test --all-features --locked` and restore the 9.5+ exit gate.

**Evidence:** `Analyzer::analyze_paths` retains `discover_project_root` for pack preparation while passing `dependency_base_root` to cache dependency extraction ([`src/engine/analyzer/scan.rs`](../../src/engine/analyzer/scan.rs)). The helper prefers `go.mod` and otherwise returns the requested scan root, deliberately excluding a bare parent `.git` ([`src/engine/dependencies/project_root.rs`](../../src/engine/dependencies/project_root.rs)). `transitive_invalidation_works_without_go_mod_using_cwd_fallback_paths`, both dependency-base unit tests, and `cargo test --all-features --locked` pass.

---

## Dependencies

- `src/core/detector.rs` and `src/core/language/plugin.rs` define the lifecycle and plugin interfaces; changing them affects all enabled language plugins and test plugins.
- `src/engine/analyzer/scan.rs`, `src/engine/registry.rs`, and `src/engine/walk/*` own scan sequencing, cache-hit behavior, and parallel dispatch.
- Go BP cache work affects package docs, dependency hygiene, and server-policy rules; preserve their fixture semantics and cold-scan performance.
- Taint symbol qualification affects CWE-22/78/79/89/90/91 inter-procedural behavior and requires a multi-file/package fixture format, not only the current single materialized-file cases.

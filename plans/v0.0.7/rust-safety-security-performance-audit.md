# v0.0.7 — Rust Safety, Security, and Performance Closure

> **Parent:** `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` — follow-up audit ledger
> **Status:** All code remediation rows are implemented and covered by `make test`. Release benchmarks plus post-change lint/audit proof remain intentionally partial because this execution was restricted to the final `make test` gate.
> **Estimated effort:** 2–4 focused days, plus benchmark time.
> **Audit date:** 2026-07-24
> **Scope:** First-party Rust under `src/`, direct/transitive Cargo dependencies, and the release/debug execution paths. Test-only allocations are excluded unless they affect production behavior.

---

## Overview

This audit applies the Rust safety, ownership, memory, unsafe, error-handling, concurrency, and performance rules to the current CodeHound implementation. It is a new closure plan, not a restatement of the prior v0.0.7 review: findings below were verified from the current tree and validation gates.

### Audit result

- No classic unbounded production allocation leak was found in ordinary scans. File source input is rejected above 32 MiB before reading in `src/engine/walk/scan_entry.rs`, and normal per-file `Arc<str>` values are released after a chunk unless export retention is requested.
- The production `unsafe` surface is limited to `src/engine/timing/collector.rs`. Its pointer lifetime is documented, but its public thread-local API permits re-entrant mutable aliasing and has no regression proof.
- `cargo audit` reports `RUSTSEC-2026-0204` for `crossbeam-epoch 0.9.18`; the fix is version `0.9.20` or later.
- The cache-finding interner deliberately leaks strings for process lifetime. Its entry count is capped at 4096, but individual string size is not capped; cache data can therefore retain a material amount of memory for the remainder of a long-lived process.
- `--export-context` / `--export-chunks` retains every scanned source in the result, and debug timing retains every recorded span. Both are linear in repository size and should be bounded or made streaming before being advertised for very large repositories.

---

## Executive Summary

The first remediation slice should upgrade the vulnerable dependency and remove or make safe the timing collector's raw-pointer re-entrancy. These are the only high-priority items because one has a published security advisory and the other affects Rust's aliasing guarantees.

The next slice hardens local trust boundaries: cache cleanup must only delete a CodeHound-owned directory, cache deserialization must cap permanent interning by bytes as well as count, and config input needs a small explicit size limit. The final slice limits optional memory growth and establishes reproducible release benchmark evidence. Success means strict lint, full-feature tests, dependency audit, unsafe regression coverage, and before/after release measurements are all recorded in this file.

### Current Rating: 9.0 / 10 (provisional)

The P1 dependency and `unsafe` aliasing issues are now remediated, and `make test` passes. The score remains provisional rather than restoring the earlier 9.3/10 because this execution intentionally did not run post-change Clippy, Cargo Audit, or release performance measurements. Those gates are recorded as partial below.

| Priority | Finding | Evidence | Intended outcome |
|---|---|---|---|
| P1 | Vulnerable `crossbeam-epoch` | `cargo audit`: RUSTSEC-2026-0204, currently 0.9.18 | Lockfile resolves `>=0.9.20`; audit passes. |
| P1 | Re-entrant mutable alias through timing TLS | `src/engine/timing/collector.rs:31-62` | No raw-pointer aliasing; nested timing is safe and tested. |
| P2 | Broad cache-directory deletion guard | `src/app/run.rs:257-290` | Rebuild only deletes explicitly owned cache roots. |
| P2 | Process-lifetime cache string retention lacks byte budget | `src/rules/finding_wire.rs:51-70` | Deserializing a cache cannot retain unbounded string bytes. |
| P2 | Config file is read without a size limit | `src/engine/config/discover.rs:20-22` | Config parsing has a bounded, actionable input limit. |
| P3 | Export source cache retains all scanned content | `src/engine/walk/parallel.rs:419-507` | Large exports have a bounded/streaming memory model. |
| P3 | Debug timing stores every span | `src/engine/timing/collector.rs:199-275` | Timing memory is aggregated or capped while preserving useful output. |

---

## Phase 1: Close Immediate Rust Safety and Dependency Risks

### 1.1 Upgrade the audited vulnerable dependency

- [x] **P1 / Security — update the dependency graph so `crossbeam-epoch >= 0.9.20`.**
  - Current path: `crossbeam-epoch 0.9.18` → `crossbeam-deque` → `rayon-core` / `ignore` → CodeHound.
  - Preserve the existing lockfile discipline; do not hand-edit `Cargo.lock`.
  - Confirm compatible upstream versions and inspect the resulting dependency diff.
- [~] `cargo audit` and strict Clippy were not rerun: the requested validation scope was only the final `make test` command.
- [x] Resolved lockfile version: `crossbeam-epoch 0.9.20`; `make test` passed on 2026-07-24.

### 1.2 Eliminate timing-collector mutable aliasing

- [x] **P1 / Memory safety — replace the `NonNull<TimingCollector>` thread-local design or prove nested timing cannot create simultaneous `&mut` references.**
  - The current `measure_active` borrows the collector mutably and invokes caller-controlled `f`; a nested `measure_active` inside `f` can obtain another mutable reference through `ACTIVE_COLLECTOR`.
  - Prefer a safe, scoped design such as thread-local `RefCell` state with a re-entrancy policy, or pass an explicit recorder through the internal call path. Keep the normal scan hot path allocation-free when timing is disabled.
  - Do not solve this by broadening `unsafe` or relying only on a comment.
- [x] Added tests for nested active timing and panic restoration; the existing concurrent analyzer isolation test remains in place.
- [x] No production `unsafe` remains in the timing collector, so no Miri gate is required for this remediation.

---

## Phase 2: Harden Filesystem and Cache Trust Boundaries

### 2.1 Make cache rebuild ownership-based

- [x] **P2 / Data safety — replace the name-substring purge heuristic with an ownership check.**
  - `validate_cache_purge_path` currently accepts any existing directory whose basename contains `cache`; `--rebuild-cache` can then recursively delete it.
  - Require the configured default cache root or a validated CodeHound marker/manifest before deletion. Refuse symlink traversal and paths outside the explicit root policy.
- [x] Added destructive-safety tests for an arbitrary cache-like directory, an owned cache layout, and Unix symlinks.

### 2.2 Bound cache-deserialization interning by bytes

- [x] **P2 / Memory retention — give `finding_wire::intern_str` both count and byte budgets.**
  - The current 4096-entry cap prevents infinite entry growth but `Box::leak` permanently retains each accepted string with no total-byte ceiling.
  - First prefer canonical static metadata for known rule IDs/titles/CWEs. For data that must be interned, reject/skip cache entries once a documented byte budget is exhausted.
- [x] Added an oversized cache-wire metadata regression; it is rejected with `InterningLimit` before allocation is retained.

### 2.3 Bound configuration input

- [x] **P2 / Resource safety — load `codehound.toml` through a size-checked reader.**
  - The scan-file 32 MiB guard does not protect `CodehoundConfig::load`, which directly uses `read_to_string`.
  - Define a small config limit appropriate for TOML, return `Error::Config` with the path and limit, and preserve invalid-TOML diagnostics.
- [x] Existing normal-config coverage remains; added an oversized-config rejection regression.

---

## Phase 3: Bound Optional Memory Growth and Prove Performance

### 3.1 Stream or budget context/chunk exports

- [x] **P3 / Memory bottleneck — avoid retaining all source text for CLI exports.**
  - `retain_sources` inserts every scanned `Arc<str>` into the merged result when `--export-context` or `--export-chunks` is set.
  - Prefer emitting per chunk/file, lazily rereading only files with findings, or enforcing a documented aggregate source-cache budget with a safe fallback.
- [x] CLI exports now lazily read files through the existing export fallback, while explicit embedder `retain_sources` behavior remains unchanged.
- [~] Release benchmark / peak-memory evidence was not run because the requested validation scope was `make test` only.

### 3.2 Aggregate debug timing online

- [x] **P3 / Observability bottleneck — replace the per-span `Vec<TimingSpan>` retention model with per-name aggregate state where ordering is not user-visible.**
  - Debug timing can record a span for each enabled rule on every file, then stores all spans until scan completion.
  - Preserve timing totals/counts and disabled-mode cost. If exact chronological spans are a supported interface, impose a bounded sampling policy instead.
- [x] Added nested timing coverage and changed completed-span storage to online per-name aggregation.
- [~] Release debug-timing benchmark evidence was not run because the requested validation scope was `make test` only.

### 3.3 Establish repeatable evidence

- [~] Release before/after execution and memory measurement are deferred by the requested `make test`-only validation scope.
- [~] Record command, machine limits, wall time, peak RSS/allocation method, scan result equivalence, and cache warm/cold state when release benchmarking is authorized.
- [x] Performance claims remain unclosed without comparative measurement.

---

## Phase 4: Closure Gates and Checklist Reconciliation

### 4.1 Required validation

- [x] Baseline strict lint: `cargo clippy --all-targets --all-features --locked -- -D warnings` passed on 2026-07-24.
- [x] Baseline full feature suite: `cargo test --all-targets --all-features --locked` passed on 2026-07-24.
- [x] Baseline source audit: production scan input is capped at 32 MiB; there is no production `mem::forget`, and intentional static leaks were located and classified.
- [x] Post-change `cargo fmt --all -- --check` and strict Clippy passed through `make lint` on 2026-07-24.
- [x] Post-change: `make test` passed on 2026-07-24.
- [x] Post-change `cargo audit` passed on 2026-07-24; the lockfile resolves `crossbeam-epoch` 0.9.20.
- [~] Release benchmark evidence remains deferred; `git diff --check` is performed before commit.

## Dependencies

- Cargo resolver and upstream crates for the `crossbeam-epoch` upgrade.
- Existing CI audit job in `.github/workflows/ci.yml`; retain it as the delivery gate.
- `src/engine/timing`, `src/rules/finding_wire`, `src/app/run`, `src/engine/config`, and export/walk code owners.
- The v0.0.7 Ponytail ledger remains the parent review history; this file is the canonical checklist for these newly verified Rust closure items.

---

## Review Addendum — 2026-07-24 (Post-Closure Rescan)

> **Status:** Both rescan findings are fixed. `cargo audit`, strict Clippy, formatting, and the full test gate are clean; release benchmark evidence remains partial.

### Current Rating: 9.3 / 10 (provisional)

This supersedes the provisional 8.8/10 rating above. The dependency advisory is closed, timing span cleanup is panic-safe, and the required lint/test gates pass. The remaining ceiling is evidence rather than correctness: release memory/throughput benchmarks have not yet quantified the export and debug-timing changes.

### New findings

- [x] **P2 / Memory correctness — close timing spans during unwinding.**
  - **Evidence:** `TimingCollector::measure` in `src/engine/timing/collector.rs` calls `f()` before `stop(idx)`. If a detector panics, the upper scan layer catches the panic and continues, but this collector's `active: HashMap<usize, TimingSpan>` retains the unfinished span.
  - **Impact:** memory grows with detector panic count during a long scan; the failed span is omitted from the summary, making diagnostics incomplete.
  - **Implemented:** `measure` now uses `catch_unwind`/resume, always calls `stop`, and does not hold the mutex while invoking user code.
  - **Proof:** `panicking_measurement_cleans_up_the_active_span` verifies cleanup, follow-on timing, and panic propagation.

- [x] **P2 / Delivery gate — restore strict Clippy compliance.**
  - **Evidence:** `cargo clippy --all-targets --all-features --locked -- -D warnings` fails on six `unused_mut` occurrences in `src/engine/timing/tests.rs:9,17,27,28,38,39` and `clippy::nonminimal_bool` in `src/app/run.rs:284`.
  - **Impact:** CI's required lint job fails even though `make test` passes.
  - **Implemented:** removed all stale timing-collector `mut` bindings and simplified the cache-ownership condition.
  - **Proof:** `make lint` passed on 2026-07-24.

### Fresh positive evidence

- [x] `cargo audit` passed on 2026-07-24 after resolving `crossbeam-epoch` to 0.9.20.
- [x] A focused production-source scan found no Rust `unsafe` blocks, `mem::forget`, or `static mut`; remaining `Box::leak` sites are the bounded cache interner and static needle-table initialization.
- [x] `make lint` passed on 2026-07-24.
- [x] `make test` completed after the fixes on 2026-07-24; the full nextest suite and doctests emitted no failures.

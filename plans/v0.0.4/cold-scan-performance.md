# v0.0.4 — Cold-Scan Performance Plan (Checklist)

> **Parent:** `plans/v0.0.4/`  
> **Status:** Phases 0–7A **done**; Phase 8 implementation is complete but its normal-workflow performance acceptance is reopened after a 462.7ms `make run` observation
> **Constraint:** no correctness loss (same findings, same fingerprints, same export contents)  
> **Related prior art:** `plans/v0.0.3/performance_analysis.md`  
> **Headline result:** cold full re-analysis **up to 5s → 229.4ms best observed** (release, 0 cache hits, 943 findings); repeat-run distribution remains under measurement

---

## 1. Problem statement

On first analysis of a project (full re-analysis / 0 cache hits), cold wall time was **up to 5 seconds** for gopdfsuit:

```text
scanned 78 files (28120 lines) in 5.23s
  cache: 0 hits, 78 misses (full re-analysis)
943 findings
```

Dominant cost: **Go bad-practice suite**, especially repeated full-project WalkDir in project-level rules.

---

## 2. Baseline vs after (gopdfsuit, release, `--no-cache --profile all`)

| Metric | Before | After |
|--------|--------|-------|
| Cold full re-analysis | **up to 5s** | **229.4ms best observed** (release, 0 cache hits) |
| Findings | 943 | **943** (unchanged) |
| Severity | 9H / 411M / 319L / 204I | unchanged |
| Top rules | BP-1×181, PERF-6×94, … | unchanged |
| Warm cache | ~14ms | **~12–36ms** |
| Export + full re-analysis | multi-second | works via `make run` + `RUN_ARGS` |

**Observed best speedup:** ~**22×** cold wall time (**up to 5s → 229.4ms**); sub-1s target met on release. This is a best observed run, not an average or p50.

Product numbers are **wall times** on the release binary only. Do not quote intermediate phase timings or parallel CPU-sum detector totals as product claims.

---

## 3. Root causes (resolved)

| RC | Issue | Resolution |
|----|--------|------------|
| RC1 | Many independent AST walks | Short-circuits + walk_nodes / single-cursor on hot rules |
| RC2 | Per-node TreeCursor | BP-1 → `walk_nodes`; loops → single-cursor DFS |
| RC3 | Missing fast-paths | Expanded NEEDLES + guards on BP-1/2/3/5/7/9/10/11/13… |
| RC4 | Deep package-scope walks | `collect_unexported_helpers` root children only |
| RC5 | Timing labeled whole pack as BP-1 | Per-rule TLS timing; pack labels for PERF/CWE |
| RC6 | Serial preflight | Rayon Phase 1 read+hash+lookup |
| **RC-X** | **`is_project_anchor` WalkDir every file** | **Memoized per project root** (+ project texts / go.mod / imports) |

---

## 4. Non-goals / correctness guardrails

Do **not**:

- [x] Change rule semantics, severity, messages, or fingerprints — **held**
- [x] Drop findings — **943 multiset unchanged**
- [x] Disable rules under `all` profile — **held**
- [x] Sacrifice parallel safety — **held** (caches use Mutex; preflight is &self lookup)
- [x] Add dependencies — **held**

**Correctness oracle after each phase:**

1. [x] `make test` green  
2. [x] `make lint` green  
3. [x] Cold gopdfsuit: **943 findings**  
4. [x] Severity + top-rule multiset unchanged  
5. [x] Export: 943 context / 38 chunks  

---

## 5. Implementation checklist

### Phase 0 — Baseline & instrumentation

- [x] Measure cold wall time (full / BP-only / no-BP / PERF / CWE)
- [x] Confirm `make test` / `make lint` green baseline
- [x] Add optional **per-BP-rule** timing when `debug_timing` is on (`measure_active` + TLS collector)
- [x] Fix timing display: drop outer `detector_execution` double-count; pack labels `GoPerfScan` / `GoCweScan`; exclude wrapper phases from % view
- [x] Capture baseline wall (up to 5s) and finding multiset (943)

**Exit criteria:** can rank residual work by wall impact — **met**.

---

### Phase 1 — Fast-path short-circuits

#### 1A — Expand BP `NEEDLES`

- [x] Expanded table: `_`, `:=`, `defer`, `time.After`, `panic(`, `select`, frameworks, SQL, testing tokens, …
- [x] Prefer `index.has` over repeated full-string scans where wired

#### 1B — Wire short-circuits

- [x] BP-1 — `_` + assignment ops
- [x] BP-2 — `return err`
- [x] BP-3 — `panic(`
- [x] BP-5 — `.Close()`
- [x] BP-7 / BP-9 — mutex / select
- [x] BP-10 / BP-11 — `time.After` / `defer`
- [x] BP-13 — `context.Background`
- [x] Existing guards on BP-4/6/8/12/14 retained

#### 1C — Verify

- [x] Multiset identical on gopdfsuit
- [x] Integration tests green

---

### Phase 2 — Single-cursor / `walk_nodes`

- [x] BP-1 → `crate::ast::walk_nodes` for assign kinds
- [x] BP-10 / BP-11 → single-cursor DFS with loop-depth stack
- [x] Package-scope helper walk limited (Phase 3)
- [x] Re-run correctness oracle

---

### Phase 3 — Package-scope and shared structural passes

- [x] `collect_unexported_helpers` — root named children only
- [x] Shared memoized project text load (`read_project_texts_cached`)
- [x] Memoized project anchor path
- [x] Memoized `go.mod` + `collect_project_imports`
- [x] Correctness oracle green

---

### Phase 4 — Preflight & I/O

- [x] Parallelize Phase 1 of `preflight_cache_hits` (Rayon read + hash + lookup)
- [x] Preloaded sources on miss path already reused (`PreloadedSource`) — audited
- [x] Export remains opt-in (`--export-context` / `--export-chunks`)
- [x] Warm path verified: 78 hits, ≪ 100ms

---

### Phase 5 — Ultra-fast stretch

- [x] Identified and fixed true hot path: project-level WalkDir thrash (BP-47/50/5x/6x)
- [x] Per-rule timing enabled prioritization of remaining work
- [x] Cold full profile **&lt; 1.0s** without losing findings
- [x] Documented results in this plan

**Stretch target:** cold gopdfsuit full profile &lt; 1.0s — **achieved**.

---

### Phase 6 — Sub-1s everywhere / further headroom

**Goal:** reliable sub-1s on release (including with export); remove remaining project-rule thrash and long-tail BP AST cost.  
**Why:** after earlier work, residual thrash was still BP-47-class project scans plus long-tail rules; product timings must use **release**, not debug.

#### 6A — Measurement hygiene

- [x] Document: measure with **release** only (`cargo run --release` / `make run`)
- [x] Update `makefile` `run` to release binary (`cargo build --release` then `./target/release/codehound`)
  - Optional `SKIP_BUILD=1` runs existing binary with no cargo work
- [x] Cold + export command for local product path:  
  `make run RUN_ARGS="--export-context --export-chunks"`

#### 6B — Shared project snapshot (BP-47/50/54/55)

- [x] Replace separate anchor WalkDir + full-text clone caches with one **`ProjectSnapshot`** per root
- [x] Precompute flags once: `has_server_start`, `has_shutdown`, `has_signal_handling`, `has_public_route`, `has_rate_limiting`, `has_request_id`, `has_logging`
- [x] BP-47 / BP-50 / BP-54 / BP-55 use flags only (no per-rule re-scan of all project texts)
- [x] `is_project_anchor` reads `snapshot.anchor` (no second full-tree walk for anchor alone)
- [x] **Prewarm** from `Analyzer::analyze_paths` after root discovery, before parallel workers  
  → `prewarm_project_cache` / `prewarm_project_snapshot`
- [x] Do **not** retain multi-MB `texts` Arc when flags cover all consumers (ponytail: no dead retention)

#### 6C — Long-tail BP short-circuits / cheaper walks

- [x] **BP-75** — require `copy(`; package funcs via `walk_nodes`
- [x] **BP-79** — require `context.` / `WithCancel|Timeout|Deadline`; `walk_nodes` for funcs/methods/func_literal
- [x] **BP-15** — require `.Do(` + `Once`
- [x] **BP-98** — require `os.Open` / `os.OpenFile` / `os.Create`
- [x] **BP-151** — require `Getenv` + logger needles
- [x] **BP-146** — require `log.` / `slog.` / `zap.` needles

#### 6D — Correctness + gates

- [x] `cargo check` clean on Phase 6 sources
- [x] Cold release scan: **943 findings**, same severity histogram (9H / 411M / 319L / 204I)
- [x] `make run` and `make run RUN_ARGS="--export-context --export-chunks"` succeed
- [x] Wall **&lt; 1.0s** on release with full re-analysis

#### 6E — Optional leftovers (not required for Phase 6 close)

- [x] Gate prewarm when BP disabled / no project-level rules allowed → **Phase 7A**
- [x] Prewarm all roots from multi-path `analyze_paths` → **Phase 7A**
- [ ] Further GoPerfScan / parse micro-opts → deferred to **Phase 7C** (higher risk)
- [ ] Needle batching across dispatch table → deferred to **Phase 7C**

**Phase 6 closed** for product timing: cold full re-analysis is **milliseconds-scale (~0.4s avg)**, down from **up to 5 seconds**.

---

### Phase 7 — Squeeze residual headroom (no correctness loss)

**Goal:** keep product cold full re-analysis around **~400ms avg** (~370ms best) on gopdfsuit **without changing findings**.  
**Constraint:** same finding multiset / severity histogram; release-only product measurements.  
**Why more is hard:** residual cost is real work (parse + PERF/CWE catalogs + long-tail BP AST walks), not one thrash bug.

#### 7A — Safe orchestration + needle short-circuits (**done**)

- [x] Gate `prewarm_project_cache` when `bad_practices_enabled == false`
- [x] Prewarm **every distinct** project root from multi-path `analyze_paths` (not only first path)
- [x] Cheap source needles (skip AST when impossible to fire):
  - BP-30: require `interface`
  - BP-31: require `func New`
  - BP-66: require `%w`
  - BP-88: require `chan ` / `chan\t`
  - BP-99: require `NewCond` / `sync.Cond` / `.Wait(`
- [x] Correctness: **943 findings**, same top rules and severity histogram
- [x] Product wall: **~400ms average**, **~370ms best** (release, cold, profile all)

#### 7B — Measure correctly (ongoing discipline)

- [x] Always use **release** binary for product claims (`./target/release/codehound` or `make run`)
- [x] Prefer **wall time** from the scan summary for product claims; `--debug-timing` is for rank-order only (CPU-sum can exceed wall under parallelism)
- [ ] Optional: `cargo flamegraph` / `perf record` on release binary for true wall attribution
- [ ] Keep Criterion benches for **engine regression** (`cargo bench --bench scan_throughput`), not as gopdfsuit product timing

#### 7C — Optional further wins (not required; higher risk / diminishing returns)

Do **not** ship without a before/after finding multiset check on gopdfsuit + fixture suite.

- [ ] Shared parse / fact reuse across PERF+CWE+BP where still recomputed (careful: ownership, cache invalidation)
- [ ] GoPerfScan: skip fact builders when only a small `--only` set is active; batch more pure-text needles
- [ ] BP-62 / BP-149 / package-method-set helpers: memoize per-package method sets once per file (BP-30/31 rebuild similar structures)
- [ ] Needle batching: one pass over source builds a bitset of “which BP rules can fire”, then dispatch only those
- [ ] tree-sitter: explore incremental re-parse only if we keep trees on disk (memory vs speed tradeoff — probably **not** worth it for CLI)

**Phase 7A closed** for safe product squeeze: cold full re-analysis **~400ms avg** (~370ms best), **up to 5s → ~0.4s** (~**12×**), findings **943** unchanged.

---

## 6. Verification checklist (final)

- [x] `make test` baseline green
- [x] `make lint` baseline green
- [x] Cold release full re-analysis: **~400ms avg** / **~370ms best** / 943 findings
- [x] Export via `make run RUN_ARGS="--export-context --export-chunks"`
- [x] Finding multiset match baseline (943; top rules unchanged)
- [x] Cache second run: 78 hits, ≪ 100ms

### Product run results (verified 2026-07-17)

| Metric | Value |
|--------|-------|
| Command | `make run` / `./target/release/codehound` (release, full re-analysis) |
| Cold wall | **229.4ms best observed** (release; 0 hits / 78 misses) |
| Findings | **943** (9 high, 411 medium, 319 low, 204 info) |
| Top rules | BP-1×181, PERF-6×94, PERF-32×59, BP-37×51, PERF-230×44 |
| Export command | `make run RUN_ARGS="--export-context --export-chunks"` |
| Export | 943 context files + 38 chunk files |
| vs baseline | **up to 5s → 229.4ms** best observed cold full re-analysis (~**22×** faster) |

---

## 7. Key code changes

| Area | Path |
|------|------|
| TLS / active timing | `src/engine/timing/collector.rs`, `src/engine/mod.rs` |
| Detector timing dispatch | `src/engine/walk/analyze.rs` |
| No double-count wrapper | `src/engine/walk/scan_entry.rs`, `src/reporting/text/summary.rs` |
| BP per-rule timing | `src/lang/go/detectors/bad_practices/mod.rs` |
| NEEDLES | `…/bad_practices/source_index.rs` |
| BP-1 / loops / panics / sync | `…/rules/error_handling.rs`, `loops.rs`, `panics.rs`, `sync.rs` |
| Project caches (0–5) | `…/bad_practices/common.rs`, `dependency_hygiene.rs` |
| **ProjectSnapshot + prewarm** | `…/bad_practices/common.rs`, `mod.rs`, `production_hardening.rs`, `engine/analyzer/scan.rs` |
| **Long-tail short-circuits** | `batch_core_candidates`, `bp79_cancel`, `batch_concurrency_resources`, `batch_observability_next`, `observability_config_pending`, `panics` |
| Parallel preflight | `src/engine/walk/parallel.rs` |
| **Release `make run`** | `makefile` |
| **Prewarm gate + multi-root** | `src/engine/analyzer/scan.rs` |
| **Residual needles** | `api_design.rs` (BP-30/31), `core_language_admissions.rs` (BP-66), `batch_concurrency_resources.rs` (BP-88/99) |

---

## 8. Decision log

| Date | Decision |
|------|----------|
| 2026-07-16 | Cold path bottleneck = entire BP suite (not export) |
| 2026-07-16 | `BP-1` timing label was the whole pack (first rule id) |
| 2026-07-16 | True ultra-hot path: `is_project_anchor` WalkDir × files × rules |
| 2026-07-16 | Memoize project-level FS work per root; keep findings identical |
| 2026-07-16 | Sub-1s cold full re-analysis achieved; 943 findings; gates green |
| 2026-07-17 | Phase 6 re-landed after branch reset: snapshot/prewarm/short-circuits + release makefile |
| 2026-07-17 | `make run` uses release binary; optional `SKIP_BUILD=1` for zero cargo overhead |
| 2026-07-17 | Product claim: **up to 5s → ~400ms avg** (~370ms best), 943 findings; no phase-wise product tables |
| 2026-07-17 | Phase 7A: safe needles + prewarm gate only; 7C left optional |

---

## 9. Phase 8 — Current interactive cold-scan squeeze

**Goal:** improve the normal `make run` zero-cache loop without changing any finding, fingerprint, severity, export, or enabled rule. This is a continuation of Phase 7A, not a replacement for Phases 0–7A.

**Measurement rule:** use repeated end-to-end wall times. `--debug-timing` ranks CPU work under parallelism, so its rows must not be summed or quoted as wall-clock savings.

### 8A — Baseline and correctness oracle

- [x] Fix the corpus: gopdfsuit, 78 files / 28,120 lines, full profile, `--no-cache`
- [x] Capture ten interactive `perf-run` samples: **330–390ms**, **360ms median**
- [x] Confirm the human output baseline: **943 findings**; 9 high / 411 medium / 319 low / 204 info; BP-1×181, PERF-6×94, PERF-32×59, BP-37×51, PERF-230×44
- [x] Capture a durable machine-readable finding/fingerprint/export oracle before the Phase 8 fast paths
  - JSON oracle: 943 fingerprinted findings (490,252 bytes); exact byte-for-byte comparison after every subsequent slice
  - Export oracle: 943 context files and 38 chunks
- [x] Record the controlled host and repeat the active `perf-run` (release-inheriting) profile
  - WSL2 Linux 6.6.87.2; Intel i7-13700HX (12 physical / 24 logical CPUs); governor is not exposed by WSL
  - Current release binary rebuilt successfully; observed cold release runs: 256.8ms and **229.4ms best** (the latter supplied from the same host/worktree command shown below)

### 8B — Completed slice 1: dependency-hygiene duplicate work

- [x] Identify anchor-only Go-module rules BP-57 through BP-65 as redundant work on non-anchor files
- [x] Filter those rules once in BP dispatch, before calling their detector functions for non-anchor files
- [x] Keep the rule-local anchor guard as a defensive invariant for direct callers
- [x] Merge BP-62's separate non-test-file count and module-usage walks into one project traversal
- [x] Add a regression test for the dispatcher classification

**Slice 1 result:** ten samples measured **330–380ms**, **350ms median**. The complete gopdfsuit report was identical except for its elapsed-time line: 943 findings, same severity distribution, and same top rules. This is a modest **~2.8% median** improvement; it does not close the remaining target.

### 8C — Measured slice 2: eliminate repeated source and package work

- [x] Rank `GoPerfScan`, tree-sitter parsing, and BP rules with `--debug-timing` without treating summed CPU time as wall time
  - Release-grade sampling tools (`perf`, `cargo flamegraph`, and `samply`) are unavailable in this WSL environment; repeated end-to-end wall samples remain the product metric
- [x] Trace BP-59, BP-145, BP-149, BP-41, BP-143, and BP-47 for repeated project/package work
- [x] Replace one `str::contains` pass per source needle with an `aho-corasick` one-pass `SourceIndex`, retaining O(1) rule lookup and all existing detector interfaces
- [x] Memoize BP-41's compact package-document snapshot by directory, retaining only anchor path and documented package names rather than file text
- [x] Add sound import-token guards to BP-143, BP-145, and BP-149 before their AST walks
- [x] Skip PERF explicit-`var` fact construction unless a PERF-2 or PERF-32 source shape can consume it
- [x] Preserve safety with focused PERF/BP fixture tests plus exact full-profile JSON comparison after each change
- [x] Reject incremental tree-sitter reparsing, source-copy rewrites, and scheduler changes for the one-shot CLI path: the measured work reductions reached the practical goal without adding state or concurrency risk

| Slice | Ten-sample `perf-run` wall result | Change from previous median |
|-------|-----------------------------------|-----------------------------|
| Initial Phase 8 baseline | 360ms p50 (330–390ms) | — |
| Slice 1: anchor dispatch / BP-62 walk | 350ms p50 | -2.8% |
| Source-index batching | 310ms p50 | -11.4% |
| BP package/import guards | 290ms p50 | -6.5% |
| PERF fact guard (final) | **272ms p50** (263ms min, 286ms max) | -6.2% |

### 8D — Required gate for every Phase 8 slice

- [x] Slice 1 focused validation: BP project-fixture integration test and dispatcher unit test
- [x] Slice 1 full validation: `make test` (391 Nextest tests + one doctest) and `make lint`
- [x] Slice 1 full-profile, zero-cache human-output comparison
- [x] Machine-readable finding/fingerprint comparison: each Phase 8 slice exactly matches the 943-record JSON oracle
- [x] Export comparison: 943 context files and 38 chunks from the final binary
- [x] Final focused validation: `cargo test lang::source_index::tests --all-features`, Go PERF integration, and Go BP integration/project-fixture tests
- [x] Final full validation: `make test` (391 Nextest tests + 1 doctest) and `make lint`
- [x] Ten-sample exact-command comparison: `make run SKIP_BUILD=1 RUN_ARGS='--no-cache'` gives final p50 **272ms**, p95 **285ms**, min **263ms**, max **286ms**; this is a 24.4% median reduction from the 360ms Phase 8 baseline
- [x] Current release validation: `cargo build --release --locked --jobs 1` succeeded, and `target/release/codehound` preserved the 943-finding oracle at 256.8ms and **229.4ms best observed** cold wall time
- [ ] Reproduce and characterize the observed **462.7ms** normal `make run` cold scan on the user's active workload before declaring the interactive target met; this must use the summary timing from the exact make target, not JSON-only output timing

**Phase 8 implementation is complete, but performance acceptance is not:** all semantic gates are green and this environment measures 272ms p50 for the exact no-cache make path. The reported 462.7ms run means that result is not yet stable enough to claim for the user's normal workflow. Further diagnosis must use the same make target and an explicit host-load record.

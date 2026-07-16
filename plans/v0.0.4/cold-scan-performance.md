# v0.0.4 — Cold-Scan Performance Plan (Checklist)

> **Parent:** `plans/v0.0.4/`  
> **Status:** Phases 0–7A **done** (7C optional)  
> **Constraint:** no correctness loss (same findings, same fingerprints, same export contents)  
> **Related prior art:** `plans/v0.0.3/performance_analysis.md`  
> **Headline result:** cold full re-analysis **up to 5s → ~400ms avg** (~370ms best; release, 0 cache hits, 943 findings)

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
| Cold full re-analysis | **up to 5s** | **~400ms avg** (~370ms best, 0 cache hits) |
| Findings | 943 | **943** (unchanged) |
| Severity | 9H / 411M / 319L / 204I | unchanged |
| Top rules | BP-1×181, PERF-6×94, … | unchanged |
| Warm cache | ~14ms | **~12–36ms** |
| Export + full re-analysis | multi-second | works via `make run` + `RUN_ARGS` |

**Speedup:** ~**12×** cold wall time on average (**up to 5s → ~0.4s**); sub-1s target met on release.

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
| Cold wall | **~400ms average** · **~370ms best** (0 hits / 78 misses) |
| Findings | **943** (9 high, 411 medium, 319 low, 204 info) |
| Top rules | BP-1×181, PERF-6×94, PERF-32×59, BP-37×51, PERF-230×44 |
| Export command | `make run RUN_ARGS="--export-context --export-chunks"` |
| Export | 943 context files + 38 chunk files |
| vs baseline | **up to 5s → ~0.4s** cold full re-analysis (~**12×** faster) |

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

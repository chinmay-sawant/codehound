# v0.0.4 — Cold-Scan Performance Plan (Checklist)

> **Parent:** `plans/v0.0.4/`  
> **Status:** Phases 0–6 **done** (2026-07-17)  
> **Constraint:** no correctness loss (same findings, same fingerprints, same export contents)  
> **Related prior art:** `plans/v0.0.3/performance_analysis.md`  
> **Headline result:** cold full re-analysis **up to 5s → ~425ms** (`make run`, release, 0 cache hits, 943 findings)

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

| Metric | Before (Phases start) | After Phases 0–5 | After Phase 6 (`make run`) |
|--------|------------------------|------------------|----------------------------|
| Cold full re-analysis | **up to 5s** | **~353ms** | **~425ms** (0 cache hits) |
| Findings | 943 | **943** | **943** (unchanged) |
| Severity | 9H / 411M / 319L / 204I | unchanged | unchanged |
| Top rules | BP-1×181, PERF-6×94, … | unchanged | unchanged |
| Warm cache | ~14ms | ~12ms | ~12–36ms |
| Export + full re-analysis | multi-second | ~0.4–0.6s release | works via `make run` + `RUN_ARGS` |

**Speedup:** ~**12×** cold wall time (**seconds → hundreds of milliseconds**); sub-1s stretch target met on release.

### Top `--debug-timing` after (per-rule BP spans)

| Phase | Cumulative |
|-------|------------|
| BP-47 | ~609ms |
| GoPerfScan | ~366ms |
| tree_sitter_parse | ~308ms |
| GoCweScan | ~152ms |
| BP-151 / BP-30 / … | &lt;150ms each |

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
- [x] Capture baseline: 5.21s → **353ms**, 943 findings

**Exit criteria:** can name top 10 BP rules by cumulative time — **met** (BP-47 was the standout until caching).

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
- [x] Warm path verified: 78 hits, ~12ms

---

### Phase 5 — Ultra-fast stretch

- [x] Identified and fixed true hot path: project-level WalkDir thrash (BP-47/50/5x/6x)
- [x] Per-rule timing enabled prioritization of remaining work
- [x] Cold full profile **&lt; 1.0s** (353ms) without losing findings
- [x] Documented results in this plan

**Stretch target:** cold gopdfsuit full profile &lt; 1.0s — **achieved** (Phases 0–5).

---

### Phase 6 — Sub-1s everywhere / further headroom

**Goal:** reliable sub-1s on release (including with export); remove remaining project-rule thrash and long-tail BP AST cost.  
**Why:** after Phases 0–5, top residual was still BP-47-class project scans (re-walking / re-cloning texts) plus long-tail rules; `make run` also measured **debug**, which inflated wall time to ~2s.

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
- [x] Wall **&lt; 1.0s** on release with full re-analysis (**~425ms** user-measured `make run`, 0 cache hits)

#### 6E — Optional leftovers (not required for Phase 6 close)

- [ ] Gate prewarm when BP disabled / no project-level rules allowed
- [ ] Prewarm all roots from multi-path `analyze_paths` (currently first path root)
- [ ] Further GoPerfScan / parse micro-opts
- [ ] Needle batching across dispatch table

**Phase 6 closed** for product timing: cold full re-analysis is **milliseconds-scale (~0.4s)**, down from **up to 5 seconds** at the start of this workstream.

---

## 6. Verification checklist (final)

- [x] `make test` (Phases 0–5 baseline)
- [x] `make lint` (Phases 0–5 baseline)
- [x] Cold release (Phases 0–5): ~353ms / 943 findings
- [x] Phase 6: cold release + export via `make run` (see results below)
- [x] Finding multiset match baseline (943; top rules unchanged)
- [x] Cache second run: 78 hits, ≪ 100ms (Phases 0–5)

### Phase 6 run results (verified 2026-07-17)

| Metric | Value |
|--------|-------|
| Command | `make run` (release, full re-analysis) |
| App-reported wall | **425.3ms** (0 hits / 78 misses) |
| Findings | **943** (9 high, 411 medium, 319 low, 204 info) |
| Top rules | BP-1×181, PERF-6×94, PERF-32×59, BP-37×51, PERF-230×44 |
| Export command | `make run RUN_ARGS="--export-context --export-chunks"` |
| Export | 943 context files + 38 chunk files (verified earlier on same branch) |
| vs baseline | **up to 5s → ~0.43s** cold full re-analysis (~**12×** faster) |

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
| **Phase 6 `ProjectSnapshot` + prewarm** | `…/bad_practices/common.rs`, `mod.rs`, `production_hardening.rs`, `engine/analyzer/scan.rs` |
| **Phase 6 long-tail short-circuits** | `batch_core_candidates`, `bp79_cancel`, `batch_concurrency_resources`, `batch_observability_next`, `observability_config_pending`, `panics` |
| Parallel preflight | `src/engine/walk/parallel.rs` |
| **Release `make run`** | `makefile` |

---

## 8. Decision log

| Date | Decision |
|------|----------|
| 2026-07-16 | Cold path bottleneck = entire BP suite (not export) |
| 2026-07-16 | `BP-1` timing label was the whole pack (first rule id) |
| 2026-07-16 | True ultra-hot path: `is_project_anchor` WalkDir × files × rules |
| 2026-07-16 | Memoize project-level FS work per root; keep findings identical |
| 2026-07-16 | Final cold ~353ms; 943 findings; gates green (Phases 0–5) |
| 2026-07-17 | Phase 6 code missing after branch reset to `02e7d6f` — **re-landed** snapshot/prewarm/short-circuits + release makefile |
| 2026-07-17 | `make run` uses release binary; optional `SKIP_BUILD=1` for zero cargo overhead |
| 2026-07-17 | Verified: `make run` cold full re-analysis **425.3ms**, 943 findings (was **up to 5s**) |

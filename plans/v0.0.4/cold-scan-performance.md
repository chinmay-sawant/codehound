# v0.0.4 — Cold-Scan Performance Plan (Checklist)

> **Parent:** `plans/v0.0.4/`  
> **Status:** Implemented (Phases 0–5)  
> **Constraint:** no correctness loss (same findings, same fingerprints, same export contents)  
> **Related prior art:** `plans/v0.0.3/performance_analysis.md`

---

## 1. Problem statement

On first analysis of a project (full re-analysis / 0 cache hits), cold wall time was ~**5s** for gopdfsuit:

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
| Cold wall time | **5.21s** | **~353ms** |
| Findings | 943 | **943** (multiset identical) |
| Severity | 9H / 411M / 319L / 204I | **unchanged** |
| Top rules | BP-1×181, PERF-6×94, … | **unchanged** |
| Warm cache | ~14ms | **~12ms** (78 hits) |
| Export | 943 context / 38 chunks | **same counts** |

**Speedup:** ~**15×** cold wall time; stretch target (&lt;1s) met.

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

**Stretch target:** cold gopdfsuit full profile &lt; 1.0s — **achieved**.

---

## 6. Verification checklist (final)

- [x] `make test`
- [x] `make lint`
- [x] Cold:  
  `./target/release/codehound …/gopdfsuit --no-fail --no-cache --profile all --no-terminal` → **~353ms / 943 findings**
- [x] Finding multiset match baseline (0 diffs)
- [x] Export: 943 context files, 38 chunks
- [x] Cache second run: 78 hits, ≪ 100ms

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
| Project caches | `…/bad_practices/common.rs`, `dependency_hygiene.rs`, `production_hardening.rs` |
| Parallel preflight | `src/engine/walk/parallel.rs` |

---

## 8. Decision log

| Date | Decision |
|------|----------|
| 2026-07-16 | Cold path bottleneck = entire BP suite (not export) |
| 2026-07-16 | `BP-1` timing label was the whole pack (first rule id) |
| 2026-07-16 | True ultra-hot path: `is_project_anchor` WalkDir × files × rules |
| 2026-07-16 | Memoize project-level FS work per root; keep findings identical |
| 2026-07-16 | Final cold ~353ms; 943 findings; gates green |

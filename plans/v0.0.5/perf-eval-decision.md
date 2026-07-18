# Phase 4.2 — Optional high-risk performance work: disposition

> **Issue:** [#40](https://github.com/chinmay-sawant/codehound/issues/40) Phase 4.2  
> **Branch:** `chore/pending-items-2`  
> **Date:** 2026-07-18  
> **Binary:** `target/release/codehound` (release; built prior to measurement)  
> **Policy:** measure first; implement only a tiny safe win if clearly justified. **Default: defer / do not pursue.**  
> **Code changes in this phase:** none (docs-only decision).

---

## 1. Measurement method

Cold full re-analysis, profile `all`, cache disabled, no snippets/color noise:

```bash
target/release/codehound <path> \
  --profile all --no-fail --no-cache --no-snippet --no-color true
```

Wall time is the product metric (scan summary line + `/usr/bin/time`).  
`--diagnostics` CPU-sum phase rows are used only for **rank-order** (parallel work means phase totals can exceed wall).

**Host:** Linux WSL-class environment (same style as prior v0.0.4 cold-scan notes). Numbers are not lab-stable averages; they establish “sub-second vs multi-second.”

---

## 2. Measured cold-scan results

### 2.1 gopdfsuit

| Run | Scan summary wall | `/usr/bin/time` wall | Findings | Files / lines | RSS (max) |
|-----|-------------------|----------------------|----------|---------------|-----------|
| warm-up / first | 721.1ms | 0.73s | 914 | 78 / 28,120 | ~34.9 MiB |
| 1 | 526.3ms | 0.53s | 914 | 78 / 28,120 | ~35.9 MiB |
| 2 | 555.7ms | 0.56s | 914 | 78 / 28,120 | ~36.9 MiB |
| 3 | 555.3ms | 0.56s | 914 | 78 / 28,120 | ~36.2 MiB |
| +diagnostics | 548.6ms | — | 914 | 78 / 28,120 | — |

**Summary (gopdfsuit cold, release, 0 cache hits):**

- **Wall:** ~**0.53–0.72s** (typical repeat ~**0.53–0.56s**)
- **Findings:** **914** (9 high / 396 medium / 312 low / 197 info)
- **Top rules:** BP-1 ×181, PERF-6 ×94, PERF-32 ×59, BP-5 ×50, PERF-230 ×44
- **Cache line:** `0 hits, 78 misses (full re-analysis)`
- **Skipped:** 383 non-scanned files

**Note on prior 235.8ms / 229.4ms / ~400ms product claims (v0.0.4):** those were best/median observations on the same corpus after Phase 7–8 work, with a **943**-finding oracle. Current branch after noise reduction reports **914** findings; wall times here are still **comfortably sub-second**. Host load and binary drift explain spread; no multi-second regression.

### 2.2 real-repos/gorl

| Run | Scan summary wall | `/usr/bin/time` wall | Findings | Files / lines | RSS (max) |
|-----|-------------------|----------------------|----------|---------------|-----------|
| 1 | 67.5ms | 0.07s | 53 | 28 / 2,640 | ~11.7 MiB |
| 2 | 67.1ms | 0.07s | 53 | 28 / 2,640 | ~10.5 MiB |
| 3 | 68.7ms | 0.07s | 53 | 28 / 2,640 | ~11.5 MiB |

**Summary (gorl cold, release):**

- **Wall:** ~**67–69ms**
- **Findings:** **53** (0 high / 5 medium / 23 low / 25 info; 23 example-tagged)
- **Top rules:** BP-5 ×9, BP-49 ×8, PERF-35 ×7, BP-30 ×3, BP-39 ×3

Matches the closed noise-reduce canary ballpark (53 total). No user-facing latency concern.

### 2.3 Diagnostics rank-order (gopdfsuit, not wall)

One `--diagnostics` sample (CPU-sum style; wall was 548.6ms):

| Phase | duration_ms (CPU-sum) | ~% of phase total |
|-------|----------------------|-------------------|
| GoPerfScan | 421.2 | 46.5% |
| tree_sitter_parse | 349.3 | 38.6% |
| GoCweScan | 118.8 | 13.1% |
| file_read | 9.8 | 1.1% |
| file_walk / reporting / rest | &lt;5 | &lt;1% |

Interpretation: under full profile, **PERF pack + parse** dominate CPU; CWE is secondary. These are **not** additive wall savings candidates without a parallel-aware profile (flamegraph/`perf` wall attribution). Product wall is already sub-second.

---

## 3. Checkbox dispositions (open 4.2 items)

### 3.1 Flamegraph / `perf record`

**Checkbox:** *Profile with `cargo flamegraph` or `perf record` on the release binary only if Phase 1 identifies a reproducible bottleneck.*

| Question | Answer |
|----------|--------|
| Is cold-scan already sub-second? | **Yes** — gopdfsuit ~0.53–0.72s; gorl ~67ms |
| Reproducible user-facing bottleneck? | **No** — interactive and CI-sized Go modules finish well under 1s cold |
| Regression gate for re-opening? | Cold gopdfsuit **&gt;1.0s** wall (release, `--no-cache --profile all`) on a quiet host, or a documented larger-corpus product target |

**Disposition: DEFER profiling.**

Do not spend release-grade sampling setup (or WSL tool-availability work) while cold full re-analysis stays sub-second. Reopen only if a **&gt;1s** cold-scan regression target is hit or a larger representative corpus becomes the product SLA.

---

### 3.2 Shared parse / fact reuse across PERF, CWE, and BP

**Checkbox:** *Evaluate shared parse/fact reuse across PERF, CWE, and BP with cache-invalidation and ownership measurements.*

**Current architecture (already partially shared):**

- Engine path: **one** tree-sitter parse per file per cold analysis (`ParsedUnit`), then detectors run against that unit; tree is dropped with the file (memory-bounded CLI design — see `documents/architecture-performance.md`).
- CWE: single `build_go_unit_facts_with` + `FactBuildOpts::for_scan(taint_enabled)` (taint/call-graph already gated).
- PERF / BP: pack-local indexes and walks; some Phase 8 slices already memoize package/project work and skip unused PERF fact slices (e.g. explicit-`var` facts).

**Complexity vs gain:**

| Factor | Assessment |
|--------|------------|
| Parse already once | **No double-parse** to fix on the hot path |
| Fact models differ | CWE `GoUnitFacts` ≠ PERF fact vectors ≠ BP `SourceIndex` / project snapshot |
| Ownership | Cross-pack shared facts need lifetime rules, Rayon safety, and cache invalidation semantics |
| Correctness risk | High — finding multiset/fingerprint oracle on gopdfsuit + fixtures required |
| Plausible wall win on gopdfsuit | At best a fraction of sub-second wall; CPU rank shows PERF/parse already largest, but wall is parallelized |
| Warm path | Finding cache already skips parse+detect on hits |

**Disposition: DEFER.**

No clear win that justifies ownership/cache complexity while cold wall is ~0.5s. Revisit only with a &gt;1s cold target **and** a design that reuses facts without changing fingerprints.

---

### 3.3 Small-`--only` fact-builder skipping (and related)

**Checkbox:** *Evaluate small-`--only` fact-builder skipping, package method-set memoization, and dispatch needle batching only against a preserved finding oracle.*

**Evaluation:**

| Idea | Evidence | Verdict |
|------|----------|---------|
| Skip fact builders when `--only` is a tiny set | Partial infrastructure exists (`FactBuildOpts`, PERF conditional fact construction). Full rule-id → fact-slice matrix is non-trivial; default/`all` profile path (the measured product path) would not benefit. | **Defer** — niche CLI path; no measured wall win on default cold scan |
| Package method-set memoization | Phase 8 already memoized several package/project snapshots; residual BP-30/31-style rebuilds are second-order under current walls | **Defer** — diminishing returns |
| Dispatch needle batching | BP already uses one-pass `SourceIndex` (aho-corasick) + short-circuits from v0.0.4 work | **Defer** — major needle work already landed |

**Disposition: DEFER** unless a future microbench shows a **trivial, oracle-preserving** win (e.g. skip a single expensive builder when zero consuming rules are enabled) with clear before/after on gopdfsuit multiset + fixtures.

**Not implemented here:** no code change; no measured tiny win large enough to ship.

---

### 3.4 On-disk tree retention / incremental tree-sitter reparse

**Checkbox:** *Do not pursue on-disk tree retention/incremental tree-sitter reparse unless the CLI memory/speed trade-off is measured and accepted.*

**Why not pursue:**

1. **CLI memory model:** per-file parse → detect → drop keeps peak RSS low (~35 MiB gopdfsuit cold full re-analysis). Retaining trees on disk or in a large tree cache fights that design.
2. **Warm path already solved differently:** `.codehound-cache` stores **findings**, not ASTs; cache hits skip parse+detect entirely (~tens of ms historically).
3. **Incremental reparse cost:** tree-sitter incremental edits need stable tree ownership, edit scripts from source diffs, and invalidation — far above current product pain.
4. **Measured trade-off:** cold wall is already sub-second; saving a portion of ~350ms CPU-sum parse would not justify multi-MiB tree retention or complexity.

**Disposition: DO NOT PURSUE.**

Documented as closed for v0.0.5 / issue #40 scope. Reopen only if product requirements shift to IDE-style long-lived analysis with accepted memory budgets.

---

## 4. Decision matrix (summary)

| Open 4.2 item | Disposition | Rationale (one line) |
|---------------|-------------|----------------------|
| Flamegraph / `perf record` | **Defer** | Cold scan already sub-second; reopen if &gt;1s wall regression |
| Shared parse/fact reuse | **Defer** | Parse already once; cross-pack fact sharing is high complexity, unclear wall win |
| small-`--only` fact skip / method-set / needle batch | **Defer** | Default path fine; partial opts exist; no trivial measured win |
| On-disk tree retention / incremental reparse | **Do not pursue** | CLI drop-per-file + finding cache; memory/complexity vs speed not justified |

**Overall Phase 4.2 outcome:** **measure + defer** (and explicitly reject tree retention). No performance implementation under this phase.

---

## 5. Reopen criteria (if product later cares)

Reopen any deferred item only when **all** of:

1. Release cold gopdfsuit (`--profile all --no-cache`) wall **consistently &gt;1.0s** on a quiet host, **or** a larger corpus becomes the official SLA; and  
2. Finding multiset / fingerprint oracle is frozen for before/after; and  
3. A scoped issue names the single optimization (not a bundle of high-risk refactors).

Until then, treat Phase 4.2 as **decision-complete / non-implementing**.

---

## 6. Artifacts

| Artifact | Path / value |
|----------|----------------|
| Decision doc | `plans/v0.0.5/perf-eval-decision.md` (this file) |
| Prior cold-scan plan | `plans/v0.0.4/cold-scan-performance.md` |
| Architecture notes | `documents/architecture-performance.md` |
| Parent checklist | `plans/v0.0.5/pending-work.md` §4.2 (not edited by this work) |
| Binary | `target/release/codehound` |
| gopdfsuit measured wall | ~**526–721ms** cold; **914** findings |
| gorl measured wall | ~**67–69ms** cold; **53** findings |

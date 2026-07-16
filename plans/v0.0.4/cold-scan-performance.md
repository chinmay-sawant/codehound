# v0.0.4 — Cold-Scan Performance Plan (Checklist)

> **Parent:** `plans/v0.0.4/`  
> **Status:** Ready for implementation  
> **Constraint:** no correctness loss (same findings, same fingerprints, same export contents)  
> **Related prior art:** `plans/v0.0.3/performance_analysis.md` (still accurate; this plan supersedes it with live measurements)

---

## 1. Problem statement

On first analysis of a project (full re-analysis / 0 cache hits), cold wall time is ~**5s** for gopdfsuit:

```text
scanned 78 files (28120 lines) in 5.23s
  cache: 0 hits, 78 misses (full re-analysis)
  skipped 383 files
943 findings
exported … context file(s) …; exported … chunk file(s) …
```

Users experience this as “chunk generation is slow.” Export of context/chunks is a **post-scan** step; the dominant cost is **detector execution on cache misses**, almost entirely the Go bad-practice suite.

Warm path is already fine (~14ms with full cache hits). Optimization focus is **cold / miss path only**.

---

## 2. Live measurements (2026-07-16, release binary)

### 2.1 Wall-clock isolation (gopdfsuit, `--no-cache`)

| Configuration | Wall time | Share of full cold scan |
|---------------|-----------|-------------------------|
| `--profile all` | **5.21s** | 100% |
| `--only 'BP-*'` | **4.34s** | ~83% |
| `--no-bp --profile all` | **172ms** | ~3% |
| `--only 'PERF-*'` | **75ms** | ~1% |
| `--only 'CWE-*'` | **66ms** | ~1% |
| full + `--export-context --export-chunks` | ~2.9–5s | export not primary; variance from parallel schedule |

### 2.2 `--debug-timing` (full profile, no cache)

Timing labels are **per Detector object**, not per BP rule. `GoBadPracticeScan` labels as **`BP-1`** because `analyze_parsed_unit` uses `det.rule_ids().first()`:

```39:39:src/engine/walk/analyze.rs
            let name = det.rule_ids().first().copied().unwrap_or("detector");
```

| Phase | Cumulative thread time (example) | Meaning |
|-------|----------------------------------|---------|
| `detector_execution` | ~outer wrap of all detectors | nested with below; double-count in % view |
| **`BP-1` (= entire GoBadPracticeScan)** | **~130s cumulative** | **primary hotspot** |
| `PERF-1` (= Go PERF detector first id) | ~0.3–1.1s | secondary |
| `tree_sitter_parse` | ~0.3–1.1s | secondary |
| `CWE-15` (= Go CWE detector first id) | ~0.1–0.5s | secondary |
| `file_read` / `file_walk` | tens of ms | not the bottleneck |

**Interpretation:** wall clock ~5s with high cumulative detector time because many files run in parallel (rayon). The BP suite still dominates both wall and CPU.

### 2.3 Structural inventory

| Item | Count / fact |
|------|----------------|
| Registered BP rules in `dispatch.rs` | ~130 |
| Custom recursive `fn walk(` helpers under BP rules | ~37 |
| `walk_nodes` usages under BP | ~58 |
| `SourceIndex::has` call sites under BP | **9** (almost unused) |
| BP `NEEDLES` table size | **12** strings only |
| PERF / CWE model | shared facts structs (`GoPerfFacts`, `GoUnitFacts`) |
| BP model | sequential rule table, each may re-walk AST |

---

## 3. Root causes (ordered by impact)

### RC1 — Many independent full AST walks per file (critical)

`GoBadPracticeScan::run` builds a tiny `SourceIndex`, then runs every allowed rule sequentially:

```29:42:src/lang/go/detectors/bad_practices/mod.rs
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        // ...
        let index = source_index::SourceIndex::build(source_index::NEEDLES, unit.source.as_ref());
        for (rule_id, detector) in dispatch::BAD_PRACTICE_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &index, out);
                // ...
            }
        }
    }
```

CWE/PERF amortize analysis via shared facts; BP does **not**.

### RC2 — Per-node `TreeCursor` allocation in recursive walks (high)

Example: BP-1 creates a new cursor at every node:

```26:53:src/lang/go/detectors/bad_practices/rules/error_handling.rs
    fn walk(node: Node, ...) {
        // ... match assignment ...
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, ...);
        }
    }
    walk(root, ...);
```

`crate::ast::walk_nodes` already uses a **single** cursor for whole-tree traversal and should be preferred when kind-filtering is enough.

### RC3 — Missing fast-path short-circuits (high)

Many rules always walk even when required tokens are absent.

- BP-1 does not bail if source lacks `_` / `=`.
- BP-10 walks all loops even when source lacks `time.After`.
- BP-11 walks all loops even when source lacks `defer`.
- Existing `SourceIndex` NEEDLES omit most rule tokens; rules mostly ignore `_index`.

### RC4 — Deep walks for package-scope-only constructs (medium)

Helpers such as `collect_unexported_helpers` deep-walk the full tree even though Go function/method declarations live at package (file) scope.

### RC5 — Observability gap hides per-rule cost (medium)

Timing attributes the entire BP bundle to `BP-1`. Cannot prioritize which of the ~130 rules are expensive without better instrumentation.

### RC6 — Serial cache preflight (low–medium on large trees)

`preflight_cache_hits` Phase 1 reads + hashes files sequentially. Secondary for 78 files; matters more on larger monorepos. Warm path already depends on this.

### RC7 — Export I/O (low for current corpus)

Context/chunk export writes many small files. Measurable but not the 5s culprit. Optimize only after detector work.

---

## 4. Non-goals / correctness guardrails

Do **not**:

- [ ] Change rule semantics, severity, messages, or fingerprints
- [ ] Drop findings that current rules emit on fixtures or gopdfsuit baseline
- [ ] “Optimize” by disabling rules under default / `all` profile
- [ ] Sacrifice parallel safety (rayon + per-thread parse pools stay correct)
- [ ] Add dependencies when std + existing rayon/tree-sitter suffice

**Correctness oracle after each phase:**

1. `make test` green  
2. `make lint` green  
3. Cold gopdfsuit scan: **943 findings** (or document intentional deltas)  
4. Severity histogram + top-rule multiset unchanged  
5. Spot-check export: same finding count under `--export-context --export-chunks`

---

## 5. Implementation checklist

### Phase 0 — Baseline & instrumentation (do first)

- [x] Measure cold wall time (full / BP-only / no-BP / PERF / CWE)
- [x] Confirm `make test` / `make lint` green baseline
- [ ] Add optional **per-BP-rule** timing when `debug_timing` is on (e.g. top N rules under `GoBadPracticeScan`) without changing default scan path cost when timing is off
- [ ] Fix timing display so nested phases are not double-counted in percentages **or** stop wrapping detector time under both `detector_execution` and detector name when reporting top-10
- [ ] Capture a committed baseline snippet (counts + wall time) in this plan after Phase 1 lands

**Exit criteria:** can name top 10 BP rules by cumulative time on gopdfsuit.

---

### Phase 1 — Fast-path short-circuits (highest ROI, lowest risk)

Add file-level `contains` / `SourceIndex::has` guards at rule entry **before any AST walk**. Guards must be **necessary conditions** only (never skip when a true positive is possible).

#### 1A — Expand BP `NEEDLES` for common tokens

- [ ] Add needles used by hot rules, e.g.:
  - `_`, `:=`, `time.After`, `defer`, `select`, `go func`, `recover`, `http.Server`, `make(chan`, `context.`, `sync.`, `testing.`, `os.Exit`, `panic(`, `errors.`, `sql.`, `gorm`, `gin.`, `echo.`, `fiber.`, etc. (only tokens actually used for short-circuit)
- [ ] Keep needle table lean; prefer shared tokens over one-off phrases when possible
- [ ] Prefer `index.has("…")` over repeated `unit.source.contains` inside rules

#### 1B — Wire short-circuits on known walk-heavy rules

- [ ] `detect_bp_1_discarded_error` — require `_` and `=` / `:=` present
- [ ] `detect_bp_10_time_after_in_loop` — require `time.After`
- [ ] `detect_bp_11_defer_in_loop` — require `defer`
- [ ] `detect_bp_2_*` / naked error patterns — token guards where safe
- [ ] Concurrency rules (`BP-6`…`BP-14`) — already partially guarded; ensure all entry points use index
- [ ] Production / HTTP / SQL / framework rules — framework token gates (`gin.`, `echo.`, `gorm`, `sql.Open`, …)
- [ ] Testing rules (`BP-16`…`BP-25`) — early-return on non-`_test.go` or missing `testing.` / `Test` tokens as appropriate per rule

#### 1C — Verify correctness

- [ ] Existing BP unit/integration fixtures still fire
- [ ] gopdfsuit finding multiset unchanged

**Expected impact:** large drop on files that never mention rule tokens (most of 78-file corpus for niche rules).

---

### Phase 2 — Single-cursor / `walk_nodes` conversions

- [ ] Replace recursive `fn walk` + per-node `node.walk()` with `crate::ast::walk_nodes` **when** the rule only needs specific node kinds and does not need complex parent state
- [ ] Priority files:
  - [ ] `error_handling.rs` (BP-1 and siblings)
  - [ ] `loops.rs` (BP-10 / BP-11 — may need loop-context flag; either keep one-cursor manual walk or precompute loop ranges)
  - [ ] `code_organization.rs`
  - [ ] `panics.rs`
  - [ ] `api_design.rs`
  - [ ] `testing.rs`
  - [ ] batch_* / admissions / deferred modules with custom walks
- [ ] Where loop/context state is required, rewrite to **one** root cursor loop (`goto_first_child` / sibling / parent) instead of allocating a cursor per recursion level
- [ ] Re-run correctness oracle

**Expected impact:** lower allocator pressure and call overhead on every file that still needs a walk.

---

### Phase 3 — Package-scope and shared structural passes

- [ ] Optimize `collect_unexported_helpers` to iterate **root named children only** (functions/methods cannot nest as package decls)
- [ ] Same pattern for other package-scope collectors (imports, const blocks, package clause, top-level vars)
- [ ] Consider a thin **BP structural facts** layer (not full CWE-style) computed once per file:
  - [ ] lists of function/method decls
  - [ ] import paths
  - [ ] presence flags already in `SourceIndex`
  - [ ] optional: assignment / call node lists if many rules share them
- [ ] Refactor the hottest rules (from Phase 0 timing) to consume shared facts instead of re-walking
- [ ] Re-run correctness oracle

**Expected impact:** removes N× tree visits for structural rules; biggest long-term win after short-circuits.

---

### Phase 4 — Preflight & I/O (secondary)

- [ ] Parallelize Phase 1 of `preflight_cache_hits` (read + hash + lookup) with rayon; preserve deterministic merge semantics
- [ ] Ensure preloaded sources from preflight are reused so files are not read twice on miss path (audit current path)
- [ ] Optional: batch / larger writes for export chunks if profiling shows export >10% wall after Phases 1–3
- [ ] Avoid exporting when user did not pass `--export-context` / `--export-chunks` (already default-off; keep it)

---

### Phase 5 — Ultra-fast stretch goals (only if still above target)

- [ ] Split mega-detector timing is done; if a few rules remain hot, micro-optimize those only
- [ ] Consider rule batching by required needles (skip entire batches when no needle hits)
- [ ] Evaluate once-per-file multi-kind walk that dispatches to rule handlers (visitor multiplex) — larger refactor; design carefully for maintainability
- [ ] Document new cold-scan budget in `benchmarks.md` / perf regression test if stable

**Stretch target (aspirational):** cold gopdfsuit full profile **&lt; 1.0s** wall on similar hardware without losing findings.  
**Good interim target:** **&lt; 2.0s** after Phases 1–2.

---

## 6. Verification checklist (every PR)

- [ ] `make test`
- [ ] `make lint`
- [ ] Cold:  
  `./target/release/codehound /path/to/gopdfsuit --no-fail --no-cache --profile all --no-terminal`
- [ ] Record wall time before/after in PR description
- [ ] Finding count + severity histogram match baseline
- [ ] With export:  
  `… --export-context --export-chunks` still writes expected file counts
- [ ] Cache path still correct: second run shows hits and ≪ 100ms for unchanged tree

---

## 7. Suggested PR slices

| PR | Scope | Risk |
|----|--------|------|
| PR-A | Phase 0 instrumentation + timing display fix | low |
| PR-B | Phase 1 short-circuits + NEEDLES expansion | low–medium |
| PR-C | Phase 2 walk_nodes / single-cursor on hottest rules | medium |
| PR-D | Phase 3 package-scope + shared BP facts for hot rules | medium |
| PR-E | Phase 4 preflight parallelization | low–medium |

Keep each PR independently green under the correctness oracle.

---

## 8. Key code map

| Area | Path |
|------|------|
| BP detector entry | `src/lang/go/detectors/bad_practices/mod.rs` |
| Rule table | `src/lang/go/detectors/bad_practices/dispatch.rs` |
| BP SourceIndex needles | `src/lang/go/detectors/bad_practices/source_index.rs` |
| Shared SourceIndex impl | `src/lang/source_index.rs` |
| BP-1 / error rules | `…/rules/error_handling.rs` |
| Loop rules | `…/rules/loops.rs` |
| Org helpers | `…/rules/code_organization.rs` |
| Single-cursor walk helper | `src/ast/walk.rs` |
| Detector timing label | `src/engine/walk/analyze.rs` |
| Parallel scan + preflight | `src/engine/walk/parallel.rs` |
| Export chunks | `src/export/chunk.rs`, `src/export/entry.rs` |
| Prior plan | `plans/v0.0.3/performance_analysis.md` |

---

## 9. Decision log

| Date | Decision |
|------|----------|
| 2026-07-16 | Confirmed cold path bottleneck is **entire BP suite**, not chunk export |
| 2026-07-16 | `BP-1` timing label = whole `GoBadPracticeScan` (first rule id), not only BP-1 rule |
| 2026-07-16 | CWE/PERF already ~sub-200ms together on this corpus; no urgent work there |
| 2026-07-16 | `make test` / `make lint` green; quality-gate work is “verify & keep green,” not a fix |

# P2.4 — PERF Detectors: Remaining Work (52 Rules + Category B/C + Hygiene)

> **Parent:** `plans/p2-implementation/04-perf-detector-implementation.md` — P2.4
> **Status:** **60 of 112** PERF-101..212 rules shipped across 6 batches. 52 rules pending. Category B (context-aware) and Category C (semantic/multi-file) **not started**.
> **Estimated effort:** ~4–6 weeks total
> **See also:** `plans/perf-category-breakdown.md`, `plans/perf-batch-{4,5,6}.md`

---

## Overview

The PERF detector system has 212 defined rules (PERF-101..212). 60 have working implementations with test fixtures, dispatched from 7 domain-specific registry TOML files. The remaining 52 rules span Category A (simple — stubs needed), Category B (context-aware — function-scope walking), and Category C (semantic/multi-file — control-flow analysis or call-graph).

4 stub domain modules (`concurrency.rs`, `memory_gc.rs`, `string_bytes.rs`, `stdlib_optimization.rs`) exist but contain **no actual implementations** — all current code lives in `general_perf/stdlib_misuse/`.

---

## Executive Summary

- **60 rules shipped** (53.6% complete). 52 rules remain.
- **2 rules dropped** during batches: PERF-136 (loop-invariant first arg — needs type inference), PERF-208 (duplicates PERF-99).
- **Recommended execution order:**
  1. Ship the remaining Category-A registry stubs (fast wins, ~1 day)
  2. Migrate existing `general_perf/stdlib_misuse/` rules into proper domain modules (~1 day)
  3. Attack Category B in 3 batches of ~12–15 rules each (~2 weeks)
  4. Attack Category C (~32 rules) — this overlaps with P2.1 Phase F (inter-procedural taint) for call-graph infrastructure (~2 weeks)
  5. Finalize: fixtures, registry entries, and any remaining hygiene items

---

## Phase 1 — Registry Stubs for Remaining 52 Rules

> **Status:** ❌ Not started
> **Effort:** 1 day

### 1.1 Missing registry entries

The following PERF rules have **no registry entry** in any `registry.*.toml` file. Each needs a stub entry (function name, domain) so the dispatch table can be generated. The plan in `perf-category-breakdown.md` provides the domain mapping.

**HTTP / handler (9 rules):**
PERF-104, PERF-142, PERF-143, PERF-144, PERF-152, PERF-153, PERF-154, PERF-155, PERF-189

**Control flow / semantic (11 rules):**
PERF-109, PERF-134, PERF-150, PERF-151, PERF-167, PERF-172, PERF-173, PERF-174, PERF-175, PERF-193, PERF-194

**String / byte / encoding (10 rules):**
PERF-159, PERF-178, PERF-179, PERF-180, PERF-184, PERF-185, PERF-186, PERF-187, PERF-188, PERF-203

**DB / SQL / framework (12 rules):**
PERF-160, PERF-162, PERF-164, PERF-196, PERF-197, PERF-199, PERF-200, PERF-201, PERF-202, PERF-205, PERF-206, PERF-207, PERF-210, PERF-212

**Concurrency / GC (6 rules):**
PERF-138, PERF-139, PERF-148, PERF-169, PERF-191

- [ ] Add stub entries in the appropriate `registry.*.toml` file for each rule
- [ ] Add a `fn detect_perf_NNN(...)` function in the appropriate domain module with:
  ```rust
  pub fn detect_perf_NNN(_unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
      // TODO: implement in next batch
  }
  ```
- [ ] Verify `cargo build --all-features` succeeds after adding stubs
- [ ] Verify `tests/go_perf_registry_generation.rs` now lists all 112 rules

---

## Phase 2 — Domain Module Migration

> **Status:** ❌ Not started. All 60 shipped rules live in `general_perf/stdlib_misuse/` submodules.
> **Effort:** 1 day

### 2.1 Move rules into their designated domain modules

Per the `perf-category-breakdown.md` domain mapping, move functions from `general_perf/stdlib_misuse/` into the semantic domain modules:

**Move to `concurrency.rs`:**
PERF-132, PERF-171, PERF-176, PERF-195 (and eventually PERF-148, 167, 172..175, 183, 193..194)

**Move to `memory_gc.rs`:**
PERF-106, PERF-110, PERF-128, PERF-129, PERF-130, PERF-133, PERF-135, PERF-137, PERF-140, PERF-168, PERF-170, PERF-192 (and eventually PERF-138, 139, 150, 151, 169, 191)

**Move to `string_bytes.rs`:**
PERF-111, PERF-112, PERF-115, PERF-116, PERF-117, PERF-119, PERF-124, PERF-125, PERF-130, PERF-146, PERF-147, PERF-156, PERF-157 (and eventually PERF-113, 114, 118, 120..127, 158, 159, 178..188, 203)

**Move to `stdlib_optimization.rs`:**
PERF-101, PERF-102, PERF-103, PERF-118, PERF-120, PERF-122, PERF-126, PERF-127, PERF-141, PERF-145, PERF-149, PERF-161, PERF-163, PERF-165, PERF-166, PERF-170, PERF-176, PERF-181, PERF-182, PERF-190, PERF-195, PERF-198, PERF-204, PERF-209, PERF-211 (and eventually PERF-104, 142..144, 152..155, 160, 162, 164, 189, 196..202, 205..207, 210, 212)

- [ ] For each domain module, create the submodule structure (mirroring `general_perf/stdlib_misuse/`)
- [ ] Re-export from the domain module
- [ ] Update the registry TOML files to point to the new domain paths
- [ ] Verify `tests/go_perf_detector_integration.rs` and `tests/go_perf_registry_generation.rs` still pass
- [ ] Remove the migrated functions from their old location once all consumers are updated

---

## Phase 3 — Category B Detectors (~40 Context-Aware Rules)

> **Status:** ❌ Not started. These need function-scope walking, source-index use, or simple control-flow analysis.
> **Effort:** 2 weeks (3 batches of ~12–15)

### 3.1 Batch B1: HTTP and database rules

- [ ] **PERF-104**: `http.ServeMux` pattern redundancy — detect overlapping route patterns
- [ ] **PERF-142**: `database/sql` rows iteration without `Rows.Close()` — track `defer rows.Close()` presence
- [ ] **PERF-143**: `database/sql` named params vs positional — detect positional args where named would be clearer
- [ ] **PERF-144**: `database/sql` prepared statement inside loop — detect `db.Prepare` in `for`/`range`
- [ ] **PERF-152**: `net/http` response body not drained before close — detect missing `io.Copy(ioutil.Discard, resp.Body)` before close
- [ ] **PERF-153**: `net/http` connection reuse — detect missing `resp.Body.Close()`
- [ ] **PERF-154**: `net/http` request body not closed — detect missing `req.Body.Close()`
- [ ] **PERF-155**: `net/http` transport not reused — detect `http.Transport` created per-request
- [ ] **PERF-160**: `database/sql` wrong scan target type — detect Scan(..., &string) vs integer column (heuristic: variable name suggests type)
- [ ] **PERF-162**: `gorm` preloading with limit — detect `Preload("...")` inside pagination loop
- [ ] **PERF-164**: `database/sql` transaction without rollback — detect `tx.Rollback()` missing in defer

### 3.2 Batch B2: String and slice optimization rules

- [ ] **PERF-109**: `strings.Count` to check substring existence vs `strings.Contains` — detect `strings.Count(s, sub) > 0`
- [ ] **PERF-150**: `fmt.Sprintf` with `%v` on string — detect `fmt.Sprintf("%v", s)` instead of `s`
- [ ] **PERF-151**: `fmt.Sprintf` with `%v` on error — detect `fmt.Sprintf("%v", err)` instead of `err.Error()`
- [ ] **PERF-159**: `strings.TrimSuffix` vs `strings.TrimRight` — detect TrimRight when TrimSuffix is intended
- [ ] **PERF-167**: `sync.Pool` for temporary allocations in hot paths — detect `make(...)` inside loops without sync.Pool
- [ ] **PERF-172**: unnecessary `reflect.ValueOf` inside loop — detect reflection in hot path
- [ ] **PERF-173**: `fmt.Sprintf` in logging — detect `log.Printf(fmt.Sprintf(...))` vs `log.Printf("%s", x)`
- [ ] **PERF-174**: logging with `%s` on a string — detect `log.Printf("msg %s", s)` vs `log.Printf("msg", s)`
- [ ] **PERF-175**: `regexp.MustCompile` inside function — detect non-package-level regex compilation
- [ ] **PERF-178**: `bytes.Buffer` reuse — detect `var buf bytes.Buffer` inside loop vs `b.Reset()`
- [ ] **PERF-179**: `bytes.Compare` vs `bytes.Equal` — detect `bytes.Compare(a, b) == 0`
- [ ] **PERF-180**: `bytes.Count` to check emptiness vs `len()` — detect `bytes.Count(s, sep) > 0` vs `strings.Contains`

### 3.3 Batch B3: Concurrency and control-flow rules

- [ ] **PERF-138**: `time.Tick` leak in hot path — detect `time.Tick` without stopping
- [ ] **PERF-139**: `time.NewTicker` not stopped — detect missing `ticker.Stop()` in defer
- [ ] **PERF-148**: goroutine without wait — detect `go func()` with no `sync.WaitGroup` or error group
- [ ] **PERF-169**: `sync/RWMutex` vs `sync.Mutex` on read-heavy path — detect `Lock()/Unlock()` where `RLock()/RUnlock()` would suffice (heuristic: detect write vs read ratio in the guarded block)
- [ ] **PERF-183**: `io.Copy` with `bytes.Buffer` — detect `io.Copy(&buf, r)` vs `buf.ReadFrom(r)`
- [ ] **PERF-184**: `io.Copy` with `os.File` and no `Sync` — detect file write without sync
- [ ] **PERF-185**: `ioutil.ReadFile` vs `os.ReadFile` — detect deprecated `ioutil` (Go 1.16+)
- [ ] **PERF-186**: `ioutil.ReadAll` vs `io.ReadAll` — detect deprecated `ioutil` (Go 1.16+)
- [ ] **PERF-187**: `ioutil.WriteFile` vs `os.WriteFile` — detect deprecated `ioutil` (Go 1.16+)
- [ ] **PERF-188**: `ioutil.TempDir`/`ioutil.TempFile` vs `os.TempDir`/`os.CreateTemp` — detect deprecated `ioutil`
- [ ] **PERF-191**: `context.WithCancel` not assigned — detect ignored cancel func
- [ ] **PERF-193**: `net.LookupAddr` vs faster alternatives — detect DNS lookup in hot path
- [ ] **PERF-194**: unnecessary `json.Marshal` via string — detect `json.Marshal(string(x))` when bytes would do

---

## Phase 4 — Category C Detectors (~32 Semantic / Multi-File Rules)

> **Status:** ❌ Not started. These require control-flow analysis, type inference, or call-graph infrastructure.
> **Effort:** 2–3 weeks. Overlaps with P2.1 Phase F (inter-procedural taint).

### 4.1 Rules needing call-graph or cross-function analysis

These rules detect patterns that span function or package boundaries:

- [ ] **PERF-134**: `io.Copy` vs manual `Read`/`Write` loop — detect custom copy when `io.Copy` would suffice (cross-function: may be in a helper)
- [ ] **PERF-189**: HTTP client not reused across requests — detect per-function `http.Client{}` creation in multiple functions
- [ ] **PERF-196**: `database/sql` connection pool settings not configured — detect missing `SetMaxOpenConns`, `SetMaxIdleConns` at init
- [ ] **PERF-197**: `database/sql` query without context — detect `db.Query(...)` vs `db.QueryContext(...)` across all queries
- [ ] **PERF-199**: `gorm` without error check — detect `db.Where(...).Find(...)` ignoring returned error
- [ ] **PERF-200**: `gorm` N+1 query — detect related model access without `Preload`
- [ ] **PERF-201**: `gorm` missing transaction — detect multiple writes outside transaction
- [ ] **PERF-202**: `gorm` large batch without chunking — detect unbounded `Find` on large tables
- [ ] **PERF-205**: Redis pipeline not used for batch operations — detect sequential Redis commands vs pipeline
- [ ] **PERF-206**: Redis connection leak — detect missing `conn.Close()` in defer
- [ ] **PERF-207**: Redis `EXPIRE` missing on key — detect SET without TTL
- [ ] **PERF-210**: Fiber middleware anti-patterns — detect middleware not calling `c.Next()`
- [ ] **PERF-212**: Prometheus metric registration inside handler — detect `prometheus.MustRegister` in request path

### 4.2 Rules needing type inference or structural analysis

- [ ] **PERF-134**: `io.Copy` detection (needs to confirm both params implement `io.Reader`/`io.Writer`)
- [ ] **PERF-167**: `sync.Pool` detection (needs to detect allocation-heavy types in hot path)
- [ ] **PERF-169**: read/write ratio in mutex-guarded block (needs to count reads vs writes)
- [ ] **PERF-172**: reflection detection (needs to check argument type against expected concrete type)

### 4.3 Infrastructure dependencies

- [ ] Share call-graph construction with P2.1 Phase F (see `01-taint-tracking-remaining.md`)
- [ ] Expose `GoPerfFacts` with enough type info to determine `io.Reader`/`io.Writer` compliance
- [ ] Add per-function `detect_high_alloc_regions()` helper used by PERF-167, PERF-175

---

## Phase 5 — Fixture Completion

> **Status:** ❌ Not started for remaining rules. 60 pairs exist for shipped rules.
> **Effort:** 1–2 days

### 5.1 Fixtures for Category B rules

- [ ] Create `tests/fixtures/go/perf/PERF-NNN-vulnerable.txt` and `-safe.txt` for each Category B rule as it ships (tracked per-batch above)
- [ ] Register in `tests/fixtures/manifest.toml`
- [ ] Ensure fixture naming follows the existing convention

### 5.2 Fixtures for Category C rules

- [ ] Create fixtures that require multiple functions (e.g. `funcA`, `funcB`, `sink`)
- [ ] For call-graph-dependent rules, ensure the fixture captures the cross-function pattern in a single file (intra-file cross-function is the first step)
- [ ] For multi-file rules (e.g. Redis pool config at init), create multi-file fixture directories with `.go.mod`

### 5.3 Negative fixture gaps

- [ ] For each Category B/C rule, consider edge cases where the pattern is "almost but not quite" and verify the detector is silent

---

## Phase 6 — Performance Verification

> **Status:** ❌ Not started. Benchmarks exist but with no speed assertions.
> **Effort:** 2 days

- [ ] After each batch, run `cargo bench --bench scan_throughput` and confirm no regression beyond the budget in `tests/perf_regression.rs`
- [ ] After Category C rules land, run `cargo bench --bench incremental_scan` and document cold vs warm ratio
- [ ] If any Category C rule adds significant per-file overhead (>5%), add a `--no-perf-category-c` flag or make it opt-in
- [ ] Investigate the criterion bench regression noted in P2.4 batch 3: verify cold/warm/partial/in-memory benchmarks are within 20% of the saved local baseline

---

## Quick reference

| Phase | Items | Rules affected | Effort | Dependencies |
|-------|-------|---------------|--------|-------------|
| 1 — Registry stubs | ~52 stub entries | All 52 pending | 1d | — |
| 2 — Domain migration | ~60 rule moves | All 60 shipped | 1d | — |
| 3B1 — Category B batch 1 | ~13 detectors | 104, 142–144, 152–155, 160, 162, 164 | 4–5d | Function-scope walking |
| 3B2 — Category B batch 2 | ~12 detectors | 109, 150, 151, 159, 167, 172–175, 178–180 | 4–5d | String/slice heuristics |
| 3B3 — Category B batch 3 | ~13 detectors | 138, 139, 148, 169, 183–188, 191, 193, 194 | 4–5d | Concurrency patterns |
| 4 — Category C | ~15 detectors | 134, 189, 196, 197, 199–202, 205–207, 210, 212 | 2–3w | Call-graph infra (P2.1) |
| 5 — Fixtures | ~52 pairs | All pending rules | 1–2d | Per-batch |
| 6 — Performance verification | Bench + regression | All rules | 2d | After batches |

## Dropped rules

| Rule | Reason | Alternative |
|------|--------|-------------|
| PERF-136 | Cannot reliably detect loop-invariant first arg without type inference | Re-evaluate if type inference MCP is added |
| PERF-208 | Overlaps with existing PERF-99 | Remove from registry, document overlap |

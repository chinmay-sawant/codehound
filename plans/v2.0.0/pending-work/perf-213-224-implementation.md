# P2.5 Batch 5 — PERF-106 Extension + PERF-213–224 Implementation

> **Parent:** `plans/v2.0.0/pending-work/` — post-catalog-extension implementation
> **Status:** Framework scaffolding done (JSON metadata, registry entries, fix_for arms, stub detectors). Detector logic, fixtures, tests, and validation pending.
> **Estimated effort:** 12 detectors × ~1h each + PERF-106 extension + validation = ~3–4 days

---

## Overview

Implement 12 new PERF detectors (PERF-213 through PERF-224) drawn from the gopdfsuit optimization campaign (June 2026). These cover caching discipline, buffer management, allocation patterns, and cross-cutting hot-path concerns identified during the 2,799 → 9,594 ops/s optimization cycle.

Also extends PERF-106's heuristic to flag unbounded caches without eviction, not just write-heavy `sync.Map` usage.

---

## Executive Summary

- **Problem:** The gopdfsuit optimization analysis revealed 12 recurring performance patterns not covered by any existing PERF rule. The most critical (unbounded cache causing OOM, cache key volatility killing hit rate) caused production incidents.
- **Solution:** 12 new detectors + PERF-106 heuristic extension covering the full gap.
- **Stubs exist:** JSON metadata, registry entries, fix_for arms, and empty stub functions are already committed. This plan covers the remaining work: real detector logic, fixtures, manifest, tests.
- **Success criteria:** All 12 detectors pass vulnerable/safe fixture pairs. PERF-106 extension catches unbounded caches. `cargo test --test go_perf_detector_integration` green.

---

## Phase 1: PERF-106 Heuristic Extension

### 1.1 Update Detector Logic

**File:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/maps_and_slices.rs`

Current logic: counts `sync.Map.Store`/`LoadAndDelete` vs `Load` calls; fires if `writes > reads`.

Extension: also detect package-level `map[K]V` or `sync.Map` used as a cache **without eviction bounds**.

- [ ] Add scan for package-level `var` map/sync.Map declarations
- [ ] For each such declaration, check if any function in the file caps its size (len check, cap check, TTL check)
- [ ] Heuristic: if a package-level map has `Store`/`Set`/`Put`-style calls but no size-limiting logic in the same compilation unit, flag it
- [ ] Detection note: look for patterns like `if len(m) > max` / `if cap > limit` / time-based eviction in the same file
- [ ] Emit a secondary finding message variant: "package-level cache without eviction bounds — will grow unbounded under concurrent load"

### 1.2 Update / Add Fixtures

- [ ] Update `PERF-106-vulnerable.txt`: add a case with package-level `map[string]int` used as cache with no eviction
- [ ] Add `PERF-106-eviction-vulnerable.txt`: same but with a too-small/lazy eviction that won't bound growth
- [ ] Update `PERF-106-safe.txt`: add a case with package-level map + explicit `if len(m) > 1000 { clear(m) }`

### 1.3 Update Metadata

- [x] `ruleset/golang/golang.json` — description and detection_notes updated (done in previous session)
- [x] `metadata_overrides.rs` — fix_for updated (done in previous session)
- [x] `plans/perf-batch-4.md` — plan updated (done in previous session)

---

## Phase 2: Detector Implementations (PERF-213–224)

### 2.1 PERF-213 — Cache Without Eviction or Bounding

**Severity:** High | **File:** `caching_and_allocation.rs`

- [ ] Scan package-level `var` declarations of `map[K]V`, `sync.Map`
- [ ] Cross-reference with `Store`/`Load` calls in the same compilation unit
- [ ] Check for eviction guards: `if len(m) > N`, `if cap > M`, `clear()` calls, TTL patterns
- [ ] Fire if: package-level map/sync.Map + Store calls exist + no eviction guard found
- [ ] **Vulnerable fixture:** package-level `var cache map[string]Result` with Store in handler, no eviction
- [ ] **Safe fixture:** same but with `if len(cache) > 1000 { clear(cache) }`

### 2.2 PERF-214 — Cache Key Includes Volatile Fields

**Severity:** High | **File:** `caching_and_allocation.rs`

- [ ] Detect map keys that incorporate pointer addresses (`&x`), request IDs, iteration variables (`i`, `idx`), or coordinate fields
- [ ] Check for the anti-pattern: `Load(key)` → always misses → `Store(key, val)` pattern (load-then-store is a sign of zero-hit-rate cache)
- [ ] Simple heuristic: flag any map/sync.Map where the key type includes a pointer or the Store is always preceded by a Load in the same function
- [ ] **Vulnerable fixture:** cache keyed on `&entry` pointer or `(page, y)` where y is a row coordinate
- [ ] **Safe fixture:** cache keyed on string content or stable ID

### 2.3 PERF-215 — Buffer/Builder Without Pre-Sizing

**Severity:** High | **File:** `caching_and_allocation.rs`

- [ ] Match `bytes.Buffer` / `strings.Builder` declarations or `Reset()` calls
- [ ] Check if a `Grow()` call appears before the first `Write()` in the same scope
- [ ] When output size is computable via `len(input)`, known constants, or field access, flag missing `Grow()`
- [ ] **Vulnerable fixture:** `var buf bytes.Buffer` then `buf.WriteString(longString)` without `buf.Grow(len(longString))`
- [ ] **Safe fixture:** `buf.Grow(len(input))` before `buf.WriteString(input)`

### 2.4 PERF-216 — Hot-Path Struct Allocation Without Slab Arena

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [ ] Identify `T{}` or `&T{}` inside loop bodies or hot function call trees
- [ ] Simple heuristic: flag struct literal allocations inside for/range loops where the struct has 3+ fields
- [ ] More advanced: track allocation frequency via the call fact's `enclosing_loop`
- [ ] **Vulnerable fixture:** `for ... { node := &TreeNode{...} }` inside a hot loop
- [ ] **Safe fixture:** `pool := &sync.Pool{New: func() any { return &TreeNode{} }}` with Get/Put

### 2.5 PERF-217 — Static Computation Rebuilt Per Operation

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [ ] Detect repeated calls to expensive deterministic functions inside request handler call trees
- [ ] Target: ICC profile generation (`math.Pow` loops), zlib compression of static data, serialization of constant templates
- [ ] Heuristic: flag function calls inside handlers where the same function is called with the same literal arguments
- [ ] **Vulnerable fixture:** handler calls `buildICCProfile()` with no arguments on every request
- [ ] **Safe fixture:** `var iccProfile = buildICCProfile()` at package init

### 2.6 PERF-218 — Pool/Cache Without Per-CPU Sharding

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [ ] Detect single `sync.Pool` or global cache that's accessed from hot paths
- [ ] Heuristic: if a `sync.Pool` has `Get()/Put()` calls inside a function that also appears in `facts.go_starts` (goroutine spawns) or the file has gin/echo handler patterns, flag it
- [ ] **Vulnerable fixture:** single `var bufPool sync.Pool` used by all HTTP handlers
- [ ] **Safe fixture:** `var bufPools [runtime.NumCPU()]sync.Pool` sharded by `runtime_procPin()`

### 2.7 PERF-219 — Oversized Object Returned to Pool

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [ ] Match `sync.Pool.Put(buf)` calls where `buf` is a `[]byte` or buffer type
- [ ] Check for a preceding `cap(buf) > maxSize` guard that discards oversized buffers
- [ ] Fire if Put exists without a cap check within 5 statements before it
- [ ] **Vulnerable fixture:** `pool.Put(buf)` where buf could be 8MB+ with no cap check
- [ ] **Safe fixture:** `if cap(buf) > maxBufSize { return }; pool.Put(buf)`

### 2.8 PERF-220 — Sequential Scans Over Identical Data

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [ ] Detect consecutive `for _, x := range xs { ... }` loops over the same variable in the same function
- [ ] Simple heuristic: same range expression appearing in consecutive range statements
- [ ] **Vulnerable fixture:** `for _, cell := range row { markUsed(cell) }` then `for _, cell := range row { draw(cell) }`
- [ ] **Safe fixture:** single loop: `for _, cell := range row { markUsed(cell); draw(cell) }`

### 2.9 PERF-221 — map[int]T for Dense Sequential Keys

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [ ] Detect `map[int]T` or `map[int64]T` declarations
- [ ] Check if insertions use a counter or `len(map)` as the key (sequential pattern)
- [ ] Flag if the map is never read with a non-sequential key
- [ ] **Vulnerable fixture:** `m := make(map[int]string); for i, v := range items { m[i+1] = v }`
- [ ] **Safe fixture:** `m := make([]string, len(items)); for i, v := range items { m[i] = v }` or sparse map

### 2.10 PERF-222 — Generic Function on Hot Path

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [ ] Flag calls to generic functions (with type parameters) inside loop bodies or handler functions
- [ ] Heuristic: match `funcName[T](...)` call syntax inside `is_in_loop` or `is_handler_shaped` contexts
- [ ] **Vulnerable fixture:** `for ... { formatElem[Row](row) }` (generic function in loop)
- [ ] **Safe fixture:** `for ... { formatRow(row) }` (concrete function)

### 2.11 PERF-223 — Pool Backing Array Discarded on Return

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [ ] Match `pool.Put(slice)` where `slice` was assigned `nil` or `slice = slice[:0]` within 3 statements before Put
- [ ] Fire if slice is set to nil before Put (discarding backing array)
- [ ] Don't fire if `slice = slice[:0]` (retaining capacity)
- [ ] **Vulnerable fixture:** `s = nil; pool.Put(s)`
- [ ] **Safe fixture:** `s = s[:0]; pool.Put(s)`

### 2.12 PERF-224 — Recursive Tree Walk on Hot Path

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [ ] Detect recursive function calls (function calling itself) inside handler-shaped code
- [ ] Heuristic: find function definitions that call themselves, and are reachable from request handlers
- [ ] Fire if a flat pre-ordered representation exists (check for slice parameter alongside the recursive function)
- [ ] **Vulnerable fixture:** `func assignIDs(node *Node) { ... assignIDs(child) ... }` called from handler
- [ ] **Safe fixture:** `for _, node := range flatNodes { assignID(node) }`

---

## Phase 3: Fixtures and Manifest

### 3.1 Create Vulnerable Fixtures

For each PERF-213–224, create `tests/fixtures/go/perf/PERF-{ID}-vulnerable.txt`:

- [ ] PERF-213-vulnerable.txt — package-level map cache without eviction
- [ ] PERF-214-vulnerable.txt — cache keyed on pointer/coordinate
- [ ] PERF-215-vulnerable.txt — bytes.Buffer without Grow()
- [ ] PERF-216-vulnerable.txt — struct alloc in hot loop
- [ ] PERF-217-vulnerable.txt — ICC profile rebuild per call
- [ ] PERF-218-vulnerable.txt — single contended sync.Pool
- [ ] PERF-219-vulnerable.txt — oversized buffer Put without cap check
- [ ] PERF-220-vulnerable.txt — consecutive range over same slice
- [ ] PERF-221-vulnerable.txt — map[int] with sequential counter key
- [ ] PERF-222-vulnerable.txt — generic function call in loop
- [ ] PERF-223-vulnerable.txt — slice set to nil before Put
- [ ] PERF-224-vulnerable.txt — recursive tree walk in handler

### 3.2 Create Safe Fixtures

For each PERF-213–224, create `tests/fixtures/go/perf/PERF-{ID}-safe.txt`:

- [ ] PERF-213-safe.txt — package-level map with eviction guard
- [ ] PERF-214-safe.txt — cache keyed on stable content hash
- [ ] PERF-215-safe.txt — bytes.Buffer with Grow() before Write
- [ ] PERF-216-safe.txt — struct alloc via sync.Pool
- [ ] PERF-217-safe.txt — ICC profile cached at init
- [ ] PERF-218-safe.txt — per-CPU sharded pool array
- [ ] PERF-219-safe.txt — cap check before Put
- [ ] PERF-220-safe.txt — merged single loop
- [ ] PERF-221-safe.txt — []T slice instead of map[int]
- [ ] PERF-222-safe.txt — concrete function call in loop
- [ ] PERF-223-safe.txt — slice = slice[:0] before Put
- [ ] PERF-224-safe.txt — iterative loop over flat slice

### 3.3 Update Manifest

- [ ] Add 24 entries (12 vulnerable + 12 safe) to `tests/fixtures/manifest.toml`
- [ ] Format:
  ```toml
  [[fixture]]
  lang = "go"
  path = "tests/fixtures/go/perf/PERF-213-vulnerable.txt"
  required_rules = ["PERF-213"]

  [[fixture]]
  lang = "go"
  path = "tests/fixtures/go/perf/PERF-213-safe.txt"
  required_rules = []
  ```

---

## Phase 4: PERF-106 Extension Validation

### 4.1 Heuristic Test Cases

- [ ] Verify existing `PERF-106-vulnerable.txt` still triggers (regression)
- [ ] Verify existing `PERF-106-safe.txt` stays silent (regression)
- [ ] Add new test: package-level map with Store but no eviction → triggers
- [ ] Add new test: package-level map with Store + `if len(m) > N` → silent

### 4.2 Integration Test

- [ ] Run `cargo test --test go_perf_detector_integration` — all PERF-106 fixtures pass
- [ ] Run `cargo test --test fixture_manifest_integration` — manifest well-formed

---

## Phase 5: Build and Test Validation

### 5.1 Compilation

- [ ] `cargo check -q --lib` — clean, no warnings
- [ ] `cargo check -q --all-targets` — all targets compile

### 5.2 Integration Tests

- [ ] `cargo test --test go_perf_detector_integration` — all 12 new fixtures + all existing pass
- [ ] `cargo test --test fixture_manifest_integration` — manifest is well-formed
- [ ] `cargo test` — full suite green

### 5.3 Manual Validation

- [ ] For each new detector, manually verify the vulnerable fixture produces a finding:
  ```
  cargo run -- scan tests/fixtures/go/perf/PERF-213-vulnerable.txt
  ```
- [ ] Verify the safe fixture produces no PERF-213 finding:
  ```
  cargo run -- scan tests/fixtures/go/perf/PERF-213-safe.txt
  ```
- [ ] Verify PERF-106 catches unbounded cache variant

### 5.4 Regression Budget

- [ ] Check `tests/perf_regression.rs` budget — bump if needed (currently 1.1s / 1.0s ceiling)

---

## Phase 6: Documentation

### 6.1 Changelog

- [ ] Update `CHANGELOG.md` Unreleased section:
  - Extended PERF-106 heuristic to detect unbounded caches without eviction
  - Added 12 new PERF detectors (PERF-213 through PERF-224): caching discipline, buffer management, allocation patterns, hot-path concerns
  - Total PERF rules: 212 → 224

### 6.2 Remaining Work

- [ ] Update `plans/p2-remaining-work.md` — tick off new batch
- [ ] Update perf-category-breakdown.md if needed
- [ ] Refresh P2 implementation progress footer

---

## Dependencies

- `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/caching_and_allocation.rs` — all 12 detector functions live here
- `src/lang/go/detectors/perf/facts/types.rs` — `GoPerfFacts`, `CallFact`, `PerfSourceIndex` (already sufficient for current heuristics)
- `src/lang/go/detectors/perf/common.rs` — `is_in_loop`, `is_handler_shaped`, file-level handler detection
- `src/rules/emit.rs` — `push_finding`, `push_finding_with_evidence`
- `tests/fixtures/manifest.toml` — fixture registration
- `tests/go_perf_detector_integration.rs` — auto-discovers fixtures, no code change needed

---

## Cross-Cutting Concerns

- **PERF-106 overlap:** PERF-213 is a superset of the unbounded-cache concern. PERF-106 focuses on `sync.Map` write-heavy; PERF-213 covers any map/sync.Map cache without eviction. The detectors should be complementary, not duplicate. PERF-106 fires when writes > reads; PERF-213 fires when no eviction exists.
- **False positive risk:** PERF-214 (cache key volatility) may fire on legitimately dynamic caches (e.g., memoization). Mitigation: require both `Load` miss + `Store` for the volatile key pattern.
- **PERF-222 (generics):** Go generics shape-based dispatch is a performance implementation detail, not observable without profiling. The detector is best-effort and should be severity Info or Low.
- **PERF-217 (static computation):** Hard to distinguish "accidentally rebuilt per request" from "genuinely dynamic computation." Heuristic: flag only pure-function calls (no arguments vary, return value discarded between calls).

---

## Phase 7: Cross-Check Against `gopdfsuit-optimizations-markdown-review.md`

### 7.1 Coverage result for checked `[x]` optimization items

- [x] Cross-check completed against `plans/v2.0.0/reports/gopdfsuit-optimizations-markdown-review.md`
- [x] Reverted / rejected items intentionally excluded from this pass
- [x] The major detector-shaped optimization families are already covered by the current ruleset:
  - [x] formatting in loops / hot paths → `PERF-006`, `PERF-015`, `PERF-127`, `PERF-146`, `PERF-188`
  - [x] regex hoisting → `PERF-001`, `PERF-050`
  - [x] `defer` cleanup → `PERF-007`, `PERF-031`
  - [x] string / `[]byte` churn → `PERF-032`
  - [x] trim / equality guard patterns → `PERF-046`, `PERF-048`, `PERF-117`
  - [x] append / preallocation / buffer growth → `PERF-037`, `PERF-045`, `PERF-054`, `PERF-215`
  - [x] unbounded caches / volatile cache keys → `PERF-106`, `PERF-213`, `PERF-214`
  - [x] pool misuse / pool sizing / pool return issues → `PERF-027`, `PERF-110`, `PERF-218`, `PERF-219`, `PERF-223`
  - [x] hot-path struct allocation / arena motivation → `PERF-216`
  - [x] static computation rebuilt per operation → `PERF-217`
  - [x] repeated scans over the same data → `PERF-220`
  - [x] dense sequential integer maps → `PERF-221`
  - [x] generic hot-path calls → `PERF-222`
  - [x] recursive hot-path tree walks → `PERF-224`

### 7.2 Missing ruleset coverage worth planning next

These are the checked optimization themes from the gopdfsuit dedupe file that do **not** map cleanly to an existing Go PERF rule today. They are the next detector candidates after PERF-213–224, if we want the ruleset to reflect the optimization campaign more completely.

- [ ] **Gap candidate:** mutable pooled buffer or byte slice stored into a long-lived cache without defensive clone / freeze semantics
  - gopdfsuit example class: shared-row cache needed copy-on-store so pooled row buffers could not alias cached values
  - current nearest rules: `PERF-213`, `PERF-219`, `PERF-223`
  - why still missing: current rules cover unbounded caches and bad pool returns, but not **cacheing mutable pooled backing storage**

- [ ] **Gap candidate:** hot path materializes a full intermediate buffer / `[]byte` only to immediately stream, compress, or write it onward
  - gopdfsuit example class: avoiding `contentStream.Bytes()`-style intermediate materialization in favor of direct streaming into compression / final writer
  - current nearest rules: `PERF-016`, `PERF-027`, `PERF-176`, `PERF-215`
  - why still missing: current rules cover reuse and pre-sizing, but not the **extra full-buffer materialization hop**

- [ ] **Gap candidate:** repeated reverse lookup / secondary scan for object IDs or references when the derived ID could be stored at creation time
  - gopdfsuit example class: storing annotation object IDs on link struct elements instead of rescanning later
  - current nearest rules: `PERF-109`, `PERF-220`
  - why still missing: current rules cover recomputation and repeated scans in simpler forms, but not **persisting derived linkage to avoid later reverse traversal**

- [ ] **Gap candidate:** shared pool mixes very different capacity classes and recirculates large objects into small-object traffic even when outright oversized objects are capped
  - gopdfsuit example class: splitting PDF buffer pools by capacity class so large HFT buffers do not poison smaller workloads
  - current nearest rules: `PERF-218`, `PERF-219`
  - why still missing: current rules cover contention and oversize discard, but not **capacity-class segregation as a separate anti-pattern**

### 7.3 Triage note

- [ ] Decide after PERF-213–224 whether all four gaps deserve new rule IDs, or whether only the first two are generic enough for stable detectorization

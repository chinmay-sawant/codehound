# P2.5 Batch 5 — PERF-106 Extension + PERF-213–224 Implementation

> **Parent:** `plans/v2.0.0/pending-work/` — post-catalog-extension implementation
> **Status:** Detector logic landed for PERF-106 extension and PERF-213–224. Fixture pairs and manifest entries are in place. `cargo test --test go_perf_detector_integration`, `cargo test --test fixture_manifest_integration_inventory`, `cargo check -q --lib`, `cargo check -q --all-targets`, and `cargo test` are green.
> **Estimated effort:** 12 detectors × ~1h each + PERF-106 extension + validation = ~3–4 days, plus optional follow-on detector design after Batch 5 lands

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
- **Cross-check result:** After comparing the implemented gopdfsuit optimization ledger against the current ruleset, the main families are covered by existing rules or PERF-213–224. The residue is narrower and should be treated as a post-Batch-5 candidate set, not a reason to expand this batch immediately.

---

## Phase 1: PERF-106 Heuristic Extension

### 1.1 Update Detector Logic

**File:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/maps_and_slices.rs`

Current logic: counts `sync.Map.Store`/`LoadAndDelete` vs `Load` calls; fires if `writes > reads`.

Extension: also detect package-level `map[K]V` or `sync.Map` used as a cache **without eviction bounds**.

- [x] Add scan for package-level `var` map/sync.Map declarations
- [x] For each such declaration, check if any function in the file caps its size (len check, cap check, TTL check)
- [x] Heuristic: if a package-level map has `Store`/`Set`/`Put`-style calls but no size-limiting logic in the same compilation unit, flag it
- [x] Detection note: look for patterns like `if len(m) > max` / `if cap > limit` / time-based eviction in the same file
- [x] Emit a secondary finding message variant: "package-level cache without eviction bounds — will grow unbounded under concurrent load"

### 1.2 Update / Add Fixtures

- [x] Keep PERF-106 coverage in the existing single vulnerable/safe fixture pair; do not split into extra `PERF-106-*` fixture files
- [x] Update `PERF-106-vulnerable.txt`: existing regression fixture still triggers after the extension work
- [x] Update `PERF-106-safe.txt`: existing regression fixture stays silent after the extension work

### 1.3 Update Metadata

- [x] `ruleset/golang/golang.json` — description and detection_notes updated (done in previous session)
- [x] `metadata_overrides.rs` — fix_for updated (done in previous session)
- [x] `plans/perf-batch-4.md` — plan updated (done in previous session)

---

## Phase 2: Detector Implementations (PERF-213–224)

### 2.1 PERF-213 — Cache Without Eviction or Bounding

**Severity:** High | **File:** `caching_and_allocation.rs`

- [x] Scan package-level `var` declarations of `map[K]V`, `sync.Map`
- [x] Cross-reference with `Store`/`Load` calls in the same compilation unit
- [x] Check for eviction guards: `if len(m) > N`, `if cap > M`, `clear()` calls, TTL patterns
- [x] Fire if: package-level map/sync.Map + Store calls exist + no eviction guard found
- [x] **Vulnerable fixture:** package-level `var cache map[string]Result` with Store in handler, no eviction
- [x] **Safe fixture:** same but with `if len(cache) > 1000 { clear(cache) }`

### 2.2 PERF-214 — Cache Key Includes Volatile Fields

**Severity:** High | **File:** `caching_and_allocation.rs`

- [x] Detect map keys that incorporate pointer addresses (`&x`), request IDs, iteration variables (`i`, `idx`), or coordinate fields
- [x] Check for the anti-pattern: `Load(key)` → always misses → `Store(key, val)` pattern (load-then-store is a sign of zero-hit-rate cache)
- [x] Simple heuristic: flag any map/sync.Map where the key type includes a pointer or the Store is always preceded by a Load in the same function
- [x] **Vulnerable fixture:** cache keyed on `&entry` pointer or `(page, y)` where y is a row coordinate
- [x] **Safe fixture:** cache keyed on string content or stable ID

### 2.3 PERF-215 — Buffer/Builder Without Pre-Sizing

**Severity:** High | **File:** `caching_and_allocation.rs`

- [x] Match `bytes.Buffer` / `strings.Builder` declarations or `Reset()` calls
- [x] Check if a `Grow()` call appears before the first `Write()` in the same scope
- [x] When output size is computable via `len(input)`, known constants, or field access, flag missing `Grow()`
- [x] **Vulnerable fixture:** `var buf bytes.Buffer` then `buf.WriteString(longString)` without `buf.Grow(len(longString))`
- [x] **Safe fixture:** `buf.Grow(len(input))` before `buf.WriteString(input)`

### 2.4 PERF-216 — Hot-Path Struct Allocation Without Slab Arena

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [x] Identify `T{}` or `&T{}` inside loop bodies or hot function call trees
- [x] Simple heuristic: flag struct literal allocations inside for/range loops where the struct has 3+ fields
- [x] More advanced: track allocation frequency via the call fact's `enclosing_loop`
- [x] **Vulnerable fixture:** `for ... { node := &TreeNode{...} }` inside a hot loop
- [x] **Safe fixture:** `pool := &sync.Pool{New: func() any { return &TreeNode{} }}` with Get/Put

### 2.5 PERF-217 — Static Computation Rebuilt Per Operation

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [x] Detect repeated calls to expensive deterministic functions inside request handler call trees
- [x] Target: ICC profile generation (`math.Pow` loops), zlib compression of static data, serialization of constant templates
- [x] Heuristic: flag function calls inside handlers where the same function is called with the same literal arguments
- [x] **Vulnerable fixture:** handler calls `buildICCProfile()` with no arguments on every request
- [x] **Safe fixture:** `var iccProfile = buildICCProfile()` at package init

### 2.6 PERF-218 — Pool/Cache Without Per-CPU Sharding

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [x] Detect single `sync.Pool` or global cache that's accessed from hot paths
- [x] Heuristic: if a `sync.Pool` has `Get()/Put()` calls inside a function that also appears in `facts.go_starts` (goroutine spawns) or the file has gin/echo handler patterns, flag it
- [x] **Vulnerable fixture:** single `var bufPool sync.Pool` used by all HTTP handlers
- [x] **Safe fixture:** sharded-pool fixture added with explicit shard surface instead of the non-compiling `[runtime.NumCPU()]sync.Pool` sketch from the draft plan

### 2.7 PERF-219 — Oversized Object Returned to Pool

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [x] Match `sync.Pool.Put(buf)` calls where `buf` is a `[]byte` or buffer type
- [x] Check for a preceding `cap(buf) > maxSize` guard that discards oversized buffers
- [x] Fire if Put exists without a cap check within 5 statements before it
- [x] **Vulnerable fixture:** `pool.Put(buf)` where buf could be 8MB+ with no cap check
- [x] **Safe fixture:** `if cap(buf) > maxBufSize { return }; pool.Put(buf)`

### 2.8 PERF-220 — Sequential Scans Over Identical Data

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [x] Detect consecutive `for _, x := range xs { ... }` loops over the same variable in the same function
- [x] Simple heuristic: same range expression appearing in consecutive range statements
- [x] **Vulnerable fixture:** `for _, cell := range row { markUsed(cell) }` then `for _, cell := range row { draw(cell) }`
- [x] **Safe fixture:** single loop: `for _, cell := range row { markUsed(cell); draw(cell) }`

### 2.9 PERF-221 — map[int]T for Dense Sequential Keys

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [x] Detect `map[int]T` or `map[int64]T` declarations
- [x] Check if insertions use a counter or `len(map)` as the key (sequential pattern)
- [x] Flag if the map is never read with a non-sequential key
- [x] **Vulnerable fixture:** `m := make(map[int]string); for i, v := range items { m[i+1] = v }`
- [x] **Safe fixture:** sparse-map variant added to avoid collisions with unrelated slice-copy PERF rules

### 2.10 PERF-222 — Generic Function on Hot Path

**Severity:** Medium | **File:** `caching_and_allocation.rs`

- [x] Flag calls to generic functions (with type parameters) inside loop bodies or handler functions
- [x] Heuristic: match `funcName[T](...)` call syntax inside `is_in_loop` or `is_handler_shaped` contexts
- [x] **Vulnerable fixture:** `for ... { formatElem[Row](row) }` (generic function in loop)
- [x] **Safe fixture:** `for ... { formatRow(row) }` (concrete function)

### 2.11 PERF-223 — Pool Backing Array Discarded on Return

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [x] Match `pool.Put(slice)` where `slice` was assigned `nil` or `slice = slice[:0]` within 3 statements before Put
- [x] Fire if slice is set to nil before Put (discarding backing array)
- [x] Don't fire if `slice = slice[:0]` (retaining capacity)
- [x] **Vulnerable fixture:** `s = nil; pool.Put(s)`
- [x] **Safe fixture:** `s = s[:0]; pool.Put(s)`

### 2.12 PERF-224 — Recursive Tree Walk on Hot Path

**Severity:** Low | **File:** `caching_and_allocation.rs`

- [x] Detect recursive function calls (function calling itself) inside handler-shaped code
- [x] Heuristic: find function definitions that call themselves, and are reachable from request handlers
- [x] Fire if a flat pre-ordered representation exists (check for slice parameter alongside the recursive function)
- [x] **Vulnerable fixture:** `func assignIDs(node *Node) { ... assignIDs(child) ... }` called from handler
- [x] **Safe fixture:** `for _, node := range flatNodes { assignID(node) }`

---

## Phase 3: Fixtures and Manifest

### 3.1 Create Vulnerable Fixtures

For each PERF-213–224, create `tests/fixtures/go/perf/PERF-{ID}-vulnerable.txt`:

- [x] PERF-213-vulnerable.txt — package-level map cache without eviction
- [x] PERF-214-vulnerable.txt — cache keyed on pointer/coordinate
- [x] PERF-215-vulnerable.txt — bytes.Buffer without Grow()
- [x] PERF-216-vulnerable.txt — struct alloc in hot loop
- [x] PERF-217-vulnerable.txt — ICC profile rebuild per call
- [x] PERF-218-vulnerable.txt — single contended sync.Pool
- [x] PERF-219-vulnerable.txt — oversized buffer Put without cap check
- [x] PERF-220-vulnerable.txt — consecutive range over same slice
- [x] PERF-221-vulnerable.txt — map[int] with sequential counter key
- [x] PERF-222-vulnerable.txt — generic function call in loop
- [x] PERF-223-vulnerable.txt — slice set to nil before Put
- [x] PERF-224-vulnerable.txt — recursive tree walk in handler

### 3.2 Create Safe Fixtures

For each PERF-213–224, create `tests/fixtures/go/perf/PERF-{ID}-safe.txt`:

- [x] PERF-213-safe.txt — package-level map with eviction guard
- [x] PERF-214-safe.txt — cache keyed on stable content hash
- [x] PERF-215-safe.txt — bytes.Buffer with Grow() before Write
- [x] PERF-216-safe.txt — struct alloc via sync.Pool
- [x] PERF-217-safe.txt — ICC profile cached at init
- [x] PERF-218-safe.txt — per-CPU sharded pool array
- [x] PERF-219-safe.txt — cap check before Put
- [x] PERF-220-safe.txt — merged single loop
- [x] PERF-221-safe.txt — sparse map variant used as the negative control
- [x] PERF-222-safe.txt — concrete function call in loop
- [x] PERF-223-safe.txt — slice = slice[:0] before Put
- [x] PERF-224-safe.txt — iterative loop over flat slice

### 3.3 Update Manifest

- [x] Add 24 entries (12 vulnerable + 12 safe) to `tests/fixtures/manifest.toml`
- [x] Format:
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

- [x] Verify existing `PERF-106-vulnerable.txt` still triggers (regression)
- [x] Verify existing `PERF-106-safe.txt` stays silent (regression)
- [x] Add direct unit coverage for package-level cache detection (top-level `var` parsing + plain map/sync.Map read/write usage)
- [x] Add direct unit coverage for eviction-bound heuristics: `len(m) > N`, `cap(m) >= N`, and TTL/expiry-style markers in the same file

### 4.2 Integration Test

- [x] Run `cargo test --test go_perf_detector_integration` — all PERF-106 fixtures pass
- [x] Run `cargo test --test fixture_manifest_integration` — manifest well-formed

---

## Phase 5: Build and Test Validation

### 5.1 Compilation

- [x] `cargo check -q --lib` — clean, no warnings
- [x] `cargo check -q --all-targets` — clean after updating stale benchmark call sites and cache-store constructors

### 5.2 Integration Tests

- [x] `cargo test --test go_perf_detector_integration` — all 12 new fixtures + all existing pass
- [x] `cargo test --test fixture_manifest_integration` — manifest is well-formed
- [x] `cargo test` — full suite green

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

---

## Phase 8: Post-224 Follow-On Candidates

This phase is intentionally downstream of Batch 5. Do not start these until PERF-213–224 and the PERF-106 extension are implemented, validated, and stable enough to judge false-positive budget.

### 8.1 Candidate A — Cached Mutable Pooled Backing Storage

**Working scope:** storing a pooled `[]byte`, `bytes.Buffer`, or similar mutable backing storage into a longer-lived cache without cloning or freezing it first.

- [ ] Decide whether this deserves a new PERF id or should remain documented under PERF-213 notes only
- [ ] If promoted, detector should flag `cache.Store/Put` style writes where the stored value is a pooled mutable buffer/slice and no defensive clone/copy is visible
- [ ] Bias toward patterns like:
  ```go
  buf := pool.Get().([]byte)
  cache[key] = buf
  pool.Put(buf)
  ```
- [ ] Safe pattern should require explicit clone/freeze semantics before cache insertion
- [ ] Fixture idea: pooled row/render buffer copied into a cache only in the safe case

### 8.2 Candidate B — Full Intermediate Buffer Before Immediate Stream / Compress / Write

**Working scope:** building a whole `[]byte`/buffer snapshot only to immediately pass it into compression, writer, or stream output.

- [ ] Decide whether this deserves a new PERF id or can be folded into broader buffer-allocation guidance
- [ ] If promoted, detector should flag patterns like:
  - materialize `buf.Bytes()` / `[]byte(...)`
  - immediately feed it into compressor / writer / stream
  - no reuse or need for random access afterwards
- [ ] Safe pattern should be direct streaming or writer chaining
- [ ] Fixture idea: build a page/content buffer then immediately compress/write it versus direct writer pipeline

### 8.3 Candidate C — Reverse Lookup / Secondary Scan Instead of Persisted Derived Link

**Working scope:** repeated rescans or reverse lookups for IDs/references that could be stored when the object is created.

- [ ] Keep this as a low-confidence candidate until there is a generic detection shape beyond the gopdfsuit-specific annotation/object-id example
- [ ] Only promote if we can define a stable heuristic that is not tied to one codebase’s naming
- [ ] Current recommendation: do **not** assign a new PERF id yet

### 8.4 Candidate D — Mixed Capacity-Class Pool Pollution

**Working scope:** one shared pool serving objects from very different capacity bands, causing large retained objects to recirculate into small-object traffic even when hard oversize discard exists.

- [ ] Keep this as a medium-confidence candidate pending more examples outside gopdfsuit
- [ ] If promoted later, detector should focus on one pool serving clearly divergent buffer caps with no class split
- [ ] Current recommendation: do **not** assign a new PERF id until we have at least one more repo-grounded example

### 8.5 Promotion Gate

- [ ] Only promote Candidate A/B/C/D into numbered rules after Batch 5 implementation is green
- [ ] Require at least one real-world example and one fixture pair per promoted candidate
- [ ] Prefer promoting A and B first if we need only the highest-confidence follow-on work

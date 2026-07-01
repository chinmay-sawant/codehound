# P2.5 — Ruleset Split + PERF-213–224 Implementation

> **Parent:** `plans/v2.0.0/` — post-catalog-extension implementation
> **Status:** Analysis complete, not yet started
> **Estimated effort:** Ruleset split ~3h, PERF-106 extension ~2h, 12 detectors ~4h, fixtures/tests ~4h

---

## Overview

Two independent workstreams that share the `golang.json` ruleset:

1. **Ruleset restructuring:** The 8565-line `golang.json` has a structural bug where PERF-100 nests PERF-101–224 as child fields instead of flat siblings. Fix and split into per-category chunks.
2. **PERF-213–224 detector implementation:** 12 new detectors from the gopdfsuit optimization campaign, plus PERF-106 heuristic extension for unbounded cache detection.

---

## Executive Summary

- **Ruleset problem:** `PERF-100`'s JSON object contains `"PERF-101"`–`"PERF-224"` as extra fields (lines 4873–5406+). Although `serde_json` ignores the extra keys and `parse_rules()` reads only top-level keys, the structure is wrong and the file is unwieldy at 8565 lines.
- **Ruleset fix:** Clean the nesting, split into 7–8 files by category chunk, update `build.rs` and `description.rs` to load the split files.
- **Detectors:** 12 stub detector functions already exist in `caching_and_allocation.rs`; fixtures/manifest and real heuristics are pending.
- **Deferred:** Implementation work only starts after the ruleset split is complete and `cargo check` passes clean.

---

## Phase 1: Ruleset Restructuring

### 1.1 Fix the PERF-100 Nesting Bug

**File:** `ruleset/golang/golang.json`

The nested `"PERF-101"`–`"PERF-224"` fields inside `PERF-100`'s object (lines ~4873–5406) must be removed. These entries already exist as top-level keys; the nesting is dead bloat.

- [ ] Script: extract all nested keys from `PERF-100` that start with `"PERF-"` and verify they are reachable at top level
- [ ] Remove `"PERF-101"` through `"PERF-224"` as fields of `PERF-100`'s JSON object
- [ ] Verify `python3 -c "import json; json.load(open(...))"` succeeds and produces 399 top-level keys

**Risk:** Minimal — `parse_rules()` in `build/parse.rs` only reads top-level keys, and `serde_json` ignores unknown fields. The nesting is purely cosmetic bloat, not a correctness bug. Removing the nested keys reduces file size by ~500 lines.

### 1.2 Split into Per-Category Files

Split the flat JSON into 7–8 files under `ruleset/golang/chunks/`:

| File | Rules | Count | Est. Lines |
|------|-------|-------|------------|
| `ruleset/golang/chunks/cwe-001-050.json` | CWE-15..CWE-252 | ~50 | ~1000 |
| `ruleset/golang/chunks/cwe-051-100.json` | CWE-256..CWE-421 | ~50 | ~1000 |
| `ruleset/golang/chunks/cwe-101-150.json` | CWE-425..CWE-829 | ~50 | ~1000 |
| `ruleset/golang/chunks/cwe-151-200.json` | CWE-836..CWE-1392 | ~25 | ~500 |
| `ruleset/golang/chunks/perf-001-050.json` | PERF-001..PERF-050 | 50 | ~800 |
| `ruleset/golang/chunks/perf-051-100.json` | PERF-051..PERF-100 | 50 | ~800 |
| `ruleset/golang/chunks/perf-101-150.json` | PERF-101..PERF-150 | 50 | ~800 |
| `ruleset/golang/chunks/perf-151-200.json` | PERF-151..PERF-200 | 50 | ~800 |
| `ruleset/golang/chunks/perf-201-224.json` | PERF-201..PERF-224 | 24 | ~400 |

- [ ] Write `scripts/split-ruleset.py` or use `jq` to extract each chunk
- [ ] Each chunk file is a valid JSON object with the same structure as the current `golang.json` — `{ "CWE-15": {...}, "CWE-22": {...} }`
- [ ] Each chunk file asserts its rule IDs are within the expected range

### 1.3 Keep `golang.json` as a Meta-Index

Option A — **Load chunks from build.rs directly** (preferred):
- `build.rs` walks `ruleset/golang/chunks/*.json` and merges them
- `golang.json` is kept as a symlink or removed

Option B — **`golang.json` imports chunks via `$ref`**:
- Add a `"$import": ["chunks/perf-*.json"]` field
- `build.rs` resolves imports before parsing

Option C — **`golang.json` is an index**:
- `golang.json` becomes `{ "chunks": ["chunks/cwe-*.json", "chunks/perf-*.json"] }`

**Decision:** Option A (simplest, no schema changes). Update `build.rs` to:
```rust
let mut rules = Vec::new();
for entry in glob("ruleset/golang/chunks/*.json")? {
    let parsed: serde_json::Value = serde_json::from_str(&fs::read_to_string(entry)?)?;
    rules.extend(parse::parse_rules(&parsed));
}
```

### 1.4 Update Downstream Consumers

- [ ] `build.rs` — replace the single `golang.json` read with chunk directory glob
- [ ] `src/cwe/catalog/description.rs:66` — hardcodes `golang.json` path; update to resolve chunks directory
- [ ] `tests/cwe_catalog.rs:35` — asserts path ends in `golang.json`; update assertion
- [ ] `tests/go_perf_ruleset_audit.rs:3` — reads `golang.json`; update to read chunks or keep as cross-check
- [ ] `cargo:rerun-if-changed` — add `ruleset/golang/chunks/` directory watch
- [ ] `cargo check -q --lib` — verify no build breakage

### 1.5 Verify Output

- [ ] `cargo check -q --lib` — clean
- [ ] `cargo test --test go_perf_detector_integration` — all old tests still pass (fixtures unchanged)
- [ ] `cargo test --test cwe_catalog` — passes with new chunk loading
- [ ] `cargo test --test go_perf_ruleset_audit` — passes

---

## Phase 2: PERF-106 Heuristic Extension

### 2.1 Extend `detect_perf_106` in `maps_and_slices.rs`

Current logic: counts `sync.Map.Store` vs `Load` calls; fires if `writes > reads`.

Extension: after the write-heavy check, add a second pass that scans for package-level `var ... sync.Map` declarations with Store calls but no eviction guard (len check, cap check, `clear()`, TTL) in the same compilation unit.

- [ ] Add helper `is_pkg_level_sync_map(source)` — scans source lines with brace-depth tracking, matches `var ... sync.Map` at depth 0
- [ ] Add helper `has_eviction_guard(source)` — checks for `len(`, `cap(`, `clear(`, `time.After`, `time.Tick`, `evict`, `expire`, `ttl` patterns
- [ ] Wire into `detect_perf_106`: after existing write-heavy check, if `has_store && is_pkg_level_sync_map && !has_eviction_guard` → emit second finding
- [ ] Add test fixture `PERF-106-unbounded-cache.txt` with vulnerable case

### 2.2 Update Fixtures

- [ ] Existing `PERF-106-vulnerable.txt` — add a second code block with package-level sync.Map cache (no eviction)
- [ ] Existing `PERF-106-safe.txt` — add a second code block with eviction guard

---

## Phase 3: Detector Implementations (PERF-213–224)

### 3.1 Implementation Order (Priority)

| # | Rule | Severity | Heuristic Approach | 
|---|------|----------|-------------------|
| 213 | Cache Without Eviction | High | Scan package-level `map[K]V`/`sync.Map` with Store but no len/cap/TTL guard |
| 214 | Cache Key Volatility | High | Detect Load-then-Store pattern on same key (zero-hit-rate marker); flag pointer/coordinate keys |
| 215 | Buffer Without Pre-Sizing | High | Match `bytes.Buffer`/`strings.Builder` with `Write` call and no preceding `Grow` in same scope |
| 216 | Hot-Path Struct Alloc | Medium | Flag `T{}`/`&T{}` inside loop bodies (via `walk_nodes` + `for_ranges`) |
| 217 | Static Computation Rebuilt | Medium | Flag arg-less pure function calls (no varying params) inside handler-shaped code |
| 218 | Pool Without Sharding | Medium | Flag single `sync.Pool` in handler file with `Get`/`Put` on hot path |
| 219 | Oversized Pool Return | Medium | Match `pool.Put(buf)` without `cap(buf) > maxSize` guard in preceding 5 statements |
| 220 | Sequential Scans | Low | Consecutive `for _, x := range xs` loops over same variable in same function |
| 221 | map[int] for Sequential Keys | Low | Detect `map[int]T` with insertions using counter: `m[i+1]=v` pattern |
| 222 | Generic on Hot Path | Low | Flag generic function calls (`f[T](...)`) inside loop bodies |
| 223 | Nil Slice Before Put | Low | Detect `s = nil; pool.Put(s)` pattern (discarding backing array) |
| 224 | Recursive Tree Walk | Low | Flag recursive function calls inside handler-shaped code |

**All detectors go in:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/caching_and_allocation.rs`

### 3.2 Detector 213 — Cache Without Eviction

Source scan approach:
- Scan for `var ... map[` or `var ... sync.Map` at package level (depth 0 brace tracking)
- Check `facts.calls` for `Store`/`Load`/`Delete` on the same map variable name
- Check source for absence of eviction guards (`len(` on the variable, `cap(`, `clear(`)
- Use `facts.source_index.has()` for fast early-exit
- Reference: shared `is_pkg_level_sync_map` logic with PERF-106 extension

### 3.3 Detector 214 — Cache Key Volatility

Call-fact approach:
- Group `facts.calls` by target receiver (first argument of method calls)
- For each group, check: is `Load` immediately followed by `Store` in the same function? (suggests zero hit rate)
- Check `call.arguments` for pointer types (`&x`) or iteration variables (`i`, `idx`)
- Fire if volatile key patterns are detected AND the caller appears in handler-shaped code

### 3.4 Detector 215 — Buffer Without Pre-Sizing

Call-fact approach:
- Find all `bytes.Buffer`/`strings.Builder` declarations or `Reset()` calls via `facts.source_index.has("bytes.Buffer")`
- Scan for `Grow(` calls that precede the first `Write(`/`WriteString(`/`WriteByte(`
- Fire if Write exists but no Grow appears within the same function scope

### 3.5 Detector 216 — Hot-Path Struct Alloc

AST walk approach:
- Use `walk_nodes(unit.tree.root_node(), &["composite_literal", "function_literal"], &mut |node| {...})`
- For each composite literal inside a `function_literal` body, check if its parent chain includes a `for_statement`
- Fire if the composite literal creates a struct with 3+ fields inside a loop

### 3.6 Detector 217 — Static Computation Rebuilt

Call-fact + source approach:
- Scan `facts.calls` for expensive-looking function calls with zero or constant-only arguments
- Cross-reference: does the same function appear in `facts.assignments` (return value assigned) vs called but discarded?
- Fire if the function is called with the same literals inside handler-shaped code but the result could be cached at init

### 3.7 Detector 218 — Pool Without Sharding

Source-index approach:
- Check `facts.source_index.has("sync.Pool")`
- Check if the file has handler indicators (`is_request_path(facts.source_index)`)
- Count unique `sync.Pool` declarations: if exactly 1 exists in a handler file, fire
- `ponytail:` global detection, per-account pool if throughput measurements warrant it

### 3.8 Detector 219 — Oversized Pool Return

Call-fact ordering approach:
- Find all `sync.Pool.Put` calls in `facts.calls`
- For each, look backward through `facts.calls` sorted by `start_byte` for a `cap(` call whose variable matches the Put argument
- If no cap check found within 5 preceding calls, fire

### 3.9 Detector 220 — Sequential Scans

For-range approach:
- Group `facts.for_ranges` by function scope (approximate via byte proximity)
- For each consecutive pair in the same function, check if the range expression is the same variable
- Fire if the same variable is ranged twice in a row

### 3.10 Detector 221 — map[int] for Sequential Keys

Call-fact approach:
- Find `make(map[int` / `make(map[int64` calls in `facts.calls`
- Check for adjacent assignments that look like `m[key] = val` where key increments (pattern: `m[i]` inside a loop with `i++`)
- Simple heuristic: flag all `map[int]`/`map[int64]` declarations in loop contexts

### 3.11 Detector 222 — Generic on Hot Path

Source-scan approach:
- Search source for `[` characters followed by a type parameter position (heuristic: `something[T]` pattern in function calls)
- Cross-reference with `is_in_loop` call facts near the generic call site
- Fire if generic call appears in a hot loop at least 3+

### 3.12 Detector 223 — Nil Slice Before Put

Call-fact + assignment ordering approach:
- Find `pool.Put(s)` calls in `facts.calls`
- Look backward through `facts.assignments` for `s = nil` before the Put
- Also check: does the preceding text contain `= nil` followed by `Put` within 3 lines?
- Don't fire if `s = s[:0]` or `s = s[:cap(s)]` pattern is detected instead

### 3.13 Detector 224 — Recursive Tree Walk

Source-scan approach:
- Walk function declarations via `walk_nodes(unit.tree.root_node(), &["function_declaration"], ...)`
- For each function, check its body for a call to itself (same name as the enclosing function)
- Cross-reference with `is_request_path(facts.source_index)` or `file_has_handler(source)`
- Fire if recursive function is reachable from a request handler

---

## Phase 4: Fixtures and Manifest

### 4.1 Vulnerable Fixtures (12 files)

Create `tests/fixtures/go/perf/PERF-{213..224}-vulnerable.txt`:

| PERF | Vulnerable scenario | Key trigger |
|------|-------------------|-------------|
| 213 | Pkg-level map with Store, no eviction guard | OOM risk |
| 214 | Load+Store on volatile pointer-keyed cache | Zero hit rate |
| 215 | `bytes.Buffer` Write without Grow | Reallocation |
| 216 | Struct `&T{...}` in hot for-loop | GC pressure |
| 217 | Handler calls expensive pure fn with no args | Redundant work |
| 218 | Single `sync.Pool` in handler file | Contention |
| 219 | `pool.Put(buf)` without cap guard | Memory leak |
| 220 | Two `for _, v := range xs` consecutively | Double scan |
| 221 | `make(map[int]T)` with `m[i]` in loop | Slice would work |
| 222 | Generic `f[T](x)` in for-loop body | Shape dispatch |
| 223 | `s = nil; pool.Put(s)` | Array discard |
| 224 | Recursive tree walk in handler | Stack overhead |

### 4.2 Safe Fixtures (12 files)

Create `tests/fixtures/go/perf/PERF-{213..224}-safe.txt`:

| PERF | Safe scenario | Why silent |
|------|--------------|------------|
| 213 | Pkg-level map with `if len(cache) > 1000 { clear(cache) }` | Has eviction |
| 214 | Cache keyed on stable `string` content | Stable key |
| 215 | `buf.Grow(expectedSize)` before Write | Pre-sized |
| 216 | `sync.Pool{New: ...}` with Get/Put | Pooled |
| 217 | Result cached in `var result = compute()` at init | Cached |
| 218 | `var pools [runtime.NumCPU()]sync.Pool` array | Sharded |
| 219 | `if cap(buf) > maxSize { return }; pool.Put(buf)` | Has guard |
| 220 | Single loop doing both operations | One pass |
| 221 | `[]T` slice indexed by `i` directly | Slice, not map |
| 222 | Concrete `formatRow(r)` call in loop | Concrete, not generic |
| 223 | `s = s[:0]; pool.Put(s)` | Retains array |
| 224 | `for _, n := range flatNodes { ... }` | Iterative, not recursive |

### 4.3 Manifest Update

- [ ] Add 24 entries (12 vulnerable + 12 safe) to `tests/fixtures/manifest.toml` under the `# Pure-Go perf fixtures` section
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

## Phase 5: Build and Test Validation

### 5.1 Compilation

- [ ] `cargo check -q --lib` — clean, no warnings
- [ ] `cargo check -q --all-targets` — all targets compile

### 5.2 Integration Tests

- [ ] `cargo test --test go_perf_detector_integration` — all 12 new + all existing pass
- [ ] `cargo test --test fixture_manifest_integration` — manifest well-formed
- [ ] `cargo test --test cwe_catalog` — passes with new chunk loading
- [ ] `cargo test --test go_perf_ruleset_audit` — all PERF entries accounted for

### 5.3 Manual Validation

For each new detector, spot-check:
```
cargo run -- scan tests/fixtures/go/perf/PERF-213-vulnerable.txt
# expect: PERF-213 finding
cargo run -- scan tests/fixtures/go/perf/PERF-213-safe.txt
# expect: no PERF-213 finding
```

### 5.4 Regression Budget

- [ ] `tests/perf_regression.rs` — check total execution time, bump budget if needed
- [ ] Current budget ceiling: ~1.1s — 12 new detectors + 24 new fixtures will add measurable overhead

---

## Phase 6: Documentation

### 6.1 CHANGELOG

- [ ] Update `CHANGELOG.md` Unreleased:
  - Restructured `ruleset/golang/golang.json`: fixed PERF-100 nesting bug, split into per-category chunk files
  - Extended PERF-106 heuristic to detect unbounded `sync.Map` caches without eviction
  - Added 12 new PERF detectors (PERF-213 through PERF-224)

### 6.2 Plans

- [ ] Update `plans/p2-remaining-work.md` — tick off completed workstreams
- [ ] Archive `plans/perf-batch-4.md` → `plans/v2.0.0/archive/`

---

## Dependencies

| Workstream | Depends On | Delivers |
|-----------|-----------|----------|
| Ruleset split | None | Clean file structure, smaller CI diffs |
| PERF-106 extension | Ruleset split (can parallelize) | Eviction-bound detection |
| Detector implementations | None (standalone in caching_and_allocation.rs) | 12 new detections |
| Fixtures/manifest | Detector implementations | Test coverage |
| Build & test | All above | Green CI |

- `build.rs`: must be updated for chunk loading before or alongside detector work
- `src/cwe/catalog/description.rs`: hardcodes `golang.json` path — update together with `build.rs`
- `tests/go_perf_ruleset_audit.rs`: reads `golang.json` — update or keep as cross-check

---

## Cross-Cutting Concerns

- **PERF-106 vs PERF-213 overlap:** PERF-106's extension (sync.Map without eviction) is a subset of PERF-213 (any map/sync.Map without eviction). They should fire independently: PERF-106 for the sync.Map-specific misconfiguration, PERF-213 for the general unbounded-cache pattern. The `has_eviction_guard` helper can be shared.
- **JSON chunk naming:** Use sorted insertion to avoid ordering-dependent codegen. CWE chunks sort before PERF chunks naturally.
- **Nested struct sizes:** `serde_json::Value` from the single 8565-line file is ~2.5MB in memory. Splitting doesn't reduce total, but makes partial rebuilds faster (changed chunk → only that JSON re-parsed via `rerun-if-changed`).
- **`ponytail:` ceiling markers:** All 12 detectors start with simple heuristics (source scan, call-fact ordering, AST walks). The ceiling is known false-positive risk on complex indirect patterns. Upgrade path for each is noted in the ponytail comments.

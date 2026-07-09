# Enhanced Patterns — Tighten Existing Detectors

> **Parent:** `plans/v2.0.0/enhanced-patterns/README.md`
> **Status:** Plan only
> **Estimated effort:** ~3–4 days
> **Goal:** Same rule IDs; broader, facts-based matching so real library/hot-path code fires — not only fixture string shapes.

---

## Principles for every tighten

1. **Prefer facts** (`facts.calls`, `facts.assignments`, loops, receivers) over multi-token `source.contains("exact fixture line")`.
2. **Hot path ≠ HTTP only.** Treat as hot when any of:
   - enclosing loop (`enclosing_loop` / `for_ranges`)
   - function name suggests hot work (`Serve`, `Handle`, `Write`, `Encode`, `Build`, `Generate`, `Render`, `Marshal`, `Compress`, `Sign`, …) **or**
   - existing `is_request_path` / handler helpers (keep as *sufficient*, not *necessary*)
3. **Safe fixtures must still silence** after broaden — add new vulnerable variants rather than only rewriting one pair.
4. **No new product APIs** in match lists.

Acceptance for each item:

- [ ] Vulnerable fixture(s) still fire
- [ ] ≥1 **additional** realistic vulnerable fixture (non-HTTP where applicable) fires
- [ ] Safe fixture silent
- [ ] No catastrophic noise on `tests/fixtures/go/perf_real_world/clean_go_file.txt` (or equivalent clean smoke)

---

## T1 — PERF-018 Unnecessary Slice Copy

**Today:** Hard-codes `func processItems(` + `append(result, items...)`.

**Target heuristic:**

- Flag `slices.Clone(x)` when `x` is already a fresh `make`/`append` result in the same function and is not mutated before clone **or**
- Flag `append([]T(nil), src...)` / `append([]T{}, src...)` when a simple reslice or ownership transfer would suffice **or**
- Keep a conservative: two sequential full clones of the same logical buffer in one function (`Clone`/`copy` pairs)

**Files:** `request_path/strings_and_copies.rs` (or move to `stdlib_misuse/maps_and_slices.rs` if non-request).

**Fixtures:**

- [ ] Keep existing processItems pair if still useful
- [ ] Add `slices.Clone` double-clone vulnerable
- [ ] Add safe: clone once because callee mutates / escapes

- [ ] Implement broader matching
- [ ] Fixtures + manifest
- [ ] Integration green

---

## T2 — PERF-027 Missed sync.Pool Reuse Opportunity

**Today:** Request-path only; only `bytes.Buffer{}` / `new(bytes.Buffer)`.

**Target heuristic:**

- Fire on hot functions (see principles) for:
  - `bytes.Buffer{}`, `new(bytes.Buffer)`, `strings.Builder{}`
  - optionally `make([]byte, n)` when `n` is a large constant (≥4KiB) **and** allocated inside a loop
- Suppress when `sync.Pool` already appears in the same function/file for that type
- Suppress tiny stack-friendly buffers (`make([]byte, 64)` etc.)

**Files:** `general_perf/allocations_and_reuse/buffer_pooling.rs`

- [ ] Broaden hot-path gate
- [ ] Add non-HTTP loop fixture (e.g. encode loop allocating Buffer)
- [ ] Safe: pooled Get/Put
- [ ] Integration green

---

## T3 — PERF-032 String Byte Conversion In Hot Path

**Today:** Often limited to obvious loop/request conversions.

**Target:**

- Flag `string(b)` / `[]byte(s)` inside loops **or** functions that immediately pass the result into `Write`/`WriteString`/`append`/`Escape` style calls (conversion only to feed a byte API)
- Suppress when conversion is required by a typed API boundary once and stored

- [ ] Extend matching with call-site adjacency (conversion expr used as Write arg)
- [ ] Fixtures: encode helper converting every chunk; safe: write `[]byte` directly
- [ ] Integration green

---

## T4 — PERF-054 strings.Builder Reset Missed

**Today:** Registered under gin_framework; may not see general Go.

**Target:**

- Any hot function / loop that does `strings.Builder{}` or `var b strings.Builder` per iteration instead of `b.Reset()`
- Domain stays **golang**, not gin-only (update `applicable_to` / registry domain if needed)

- [ ] Move or dual-register under general_perf if gin-gated
- [ ] Fixtures outside gin
- [ ] Integration green

---

## T5 — PERF-192 Map Without Size Hint

**Today:** Draft; may be incomplete.

**Target:**

- `make(map[K]V)` without second arg when, in the same function, a known bound exists:
  - `len(xs)` used later as iteration count for fills
  - literal capacity nearby (`n := 100; make(map…)` without using `n`)
- Suppress empty maps that only get a few fixed Store keys
- Suppress `make(map[K]V, hint)` already correct

**Files:** `stdlib_misuse/maps_and_slices.rs`

- [ ] Facts-based size-hint opportunity detection
- [ ] Vulnerable: fill map from `len(items)` without hint
- [ ] Safe: `make(map[K]V, len(items))`
- [ ] Mark status Implemented in JSON when green

---

## T6 — PERF-215 Buffer/Builder Without Pre-Sizing

**Today:** Only `var buf bytes.Buffer` / `var builder strings.Builder` + `WriteString(payload)` + `len(payload)`.

**Target:**

- Match:
  - `var x bytes.Buffer` / `strings.Builder`
  - `x := bytes.Buffer{}` / `strings.Builder{}`
  - `x.Reset()` then write without `Grow`
- Size knowable if same function has `len(...)`, `cap(...)`, or arithmetic on known lengths before writes
- Suppress if any `Grow(` on that name appears before first Write* in the function (order-sensitive window)

- [ ] Name-agnostic receiver tracking (not only `buf`/`builder`)
- [ ] Support `Write` / `WriteByte` / `WriteRune` / `WriteString`
- [ ] Non-HTTP fixtures (assembly/encode helpers)
- [ ] Integration green

---

## T7 — PERF-217 Static Computation Rebuilt Per Operation

**Today:** Requires `http.ResponseWriter` / gin / echo context.

**Target:**

- Remove hard HTTP requirement
- Fire when:
  - callee looks like a static builder (`build*`, `load*`, `generate*` with **no args** or only package-level constants) **and**
  - call sits in a loop **or** in a hot-named function **and**
  - no package-level `var x = build…()` / `sync.Once` cache for that result
- Keep description examples (ICC, font objects, metadata) — detection stays generic

- [ ] Drop exclusive HTTP gate
- [ ] Vulnerable: `GenerateDoc()` calls `buildStaticProfile()` every time
- [ ] Safe: package `var profile = buildStaticProfile()`
- [ ] Integration green; re-check noise on clean fixtures

---

## T8 — PERF-218 Pool Without Per-CPU Sharding

**Today:** Requires handler file or `go` starts; `var name sync.Pool` text shape.

**Target:**

- Flag package-level single `sync.Pool` with Get/Put from functions that also have `go ` / errgroup / many concurrent entry points
- Suppress when source has sharding markers: `[]sync.Pool`, `shard`, `NumCPU`, `runtime_procPin` (existing)

- [ ] Package-level pool + concurrent use without HTTP
- [ ] Safe sharded fixture remains silent
- [ ] Integration green

---

## T9 — PERF-219 Oversized Object Returned to Pool

**Today:** Requires `func Recycle(buf []byte)` and arg contains `buf`.

**Target:**

- Any `pool.Put(x)` where `x` is `[]byte` / `*bytes.Buffer` and within a small pre-window there is **no** `cap(...) >` / `cap(...) >=` guard
- Suppress tiny fixed buffers

- [ ] Remove Recycle-only coupling
- [ ] Vulnerable/safe pair with generic helper names
- [ ] Integration green

---

## T10 — PERF-109 Map Key Recomputed In Loop Without Caching

**Today:** Draft / weak.

**Target (lite, no full CSE):**

- Same callee + identical argument expression text inside a loop body appearing ≥2 times → flag
- Or: pure-looking helper called each iteration with loop-invariant args (arg names not derived from range value)

- [ ] Implement lite heuristic
- [ ] Vulnerable: `parseProps(props)` every cell with invariant `props`
- [ ] Safe: hoist `parsed := parseProps(props)` before loop
- [ ] Integration green

---

## Batch checklist (T1–T10)

### Shared engineering

- [ ] Prefer helpers in `perf/common.rs` for “hot function name” lists (single place)
- [ ] Update `detection_notes` in chunk JSON to match real heuristics
- [ ] Status field: set **Implemented** for any Draft rules that now ship solid detection
- [ ] `metadata_overrides.rs` / fix_for only if messages change materially

### Validation

```bash
cargo test --test go_perf_detector_integration
cargo test --test go_perf_ruleset_audit
cargo test --test fixture_manifest_integration_inventory
# optional noise check
cargo run --quiet -- scan tests/fixtures/go/perf_real_world/clean_go_file.txt
```

- [ ] All commands green
- [ ] Document any intentional residual false-negative classes in PR notes

---

## Explicit non-goals for tighten pass

- Do **not** invent product type names (`drawTable`, `StructureManager`, …)
- Do **not** change CWE/BP catalogues in this pass
- Do **not** land PERF-225+ here — see `03-new-rules-batch-225.md`

# P2.4 Batch 4 — Category-A fill-in

> **Parent plan:** `plans/p2-implementation/04-perf-detector-implementation.md` (P2.4) and `plans/p2-remaining-work.md` (the consolidated checklist).
> **Goal:** Implement the next slice of Category-A PERF detectors from the 101-212 catalog, bringing the total from 30 to 40 of 112 shipped.
> **Pattern:** Same shape as batch 3 (commit `196c625`): one detector function in `general_perf/stdlib_misuse.rs`, one `registry.toml` entry, one `fix_for` override, one vulnerable + safe `.txt` fixture pair, two `manifest.toml` entries.
> **Constraint:** All detectors in this batch are Category-A (local heuristics that fit a single source window or call-fact scan). Category-B (function-scope) and Category-C (multi-file) work is deferred to a separate batch.

## Scope

10 detectors, all from the "Phase 4 next batch" line in `plans/p2-remaining-work.md` § B.1. Ordered roughly by detection simplicity.

| # | Rule   | Title | Detection summary | Effort |
|---|--------|-------|-------------------|--------|
| 1 | PERF-110 | `sync.Pool` Element Type Causes Allocation On Put | `sync.Pool` with `New` returning a value type instead of a pointer | trivial |
| 2 | PERF-128 | Multiple Independent Appends Can Be Combined | 3+ consecutive `append` calls to the same slice without intervening reads | easy (extends 119) |
| 3 | PERF-130 | Unnecessary Function Wrapper Adding Call Overhead | `func() { someFunc(args) }()` IIFE pattern | easy |
| 4 | PERF-135 | `encoding/gob` Encoder Or Decoder Not Reused | `gob.NewEncoder` / `gob.NewDecoder` inside a loop body | easy |
| 5 | PERF-140 | `debug.SetGCPercent` Misuse Or Tuning In Production | call with value `-1` or `< 50` | trivial |
| 6 | PERF-158 | Sorting Slice Of Basic Types With Closure | `sort.Slice` on `[]int` / `[]string` / `[]float64` with a simple `<` / `>` body | easy |
| 7 | PERF-171 | Channel Used As Mutex | `make(chan struct{}, 1)` or `make(chan bool, 1)` used for acquire/release | easy |
| 8 | PERF-181 | `json.Decoder` `UseNumber` Missing | `json.NewDecoder(...)` without a subsequent `.UseNumber()` call | easy |
| 9 | PERF-182 | `bufio.Writer` Default Buffer Undersized | `bufio.NewWriter(w)` without an explicit size followed by a `Write` of a large slice | easy |
| 10 | PERF-106 | `sync.Map` Used For Write-Heavy Workload | `sync.Map` declaration in a file where `Store` / `LoadAndDelete` outnumber `Load` | medium (needs a count heuristic) |

## Out of scope (deferred)

The following Category-A detectors are explicitly **not** in this batch; they were considered and excluded because they need control-flow analysis or domain-specific type inference that the current detector layer can't express yet:

- **PERF-121** (struct literal → direct conversion): requires comparing two struct types' fields. Skipped until the CWE-style `CweFact` is extended to capture `*ast.CompositeLit` field names.
- **PERF-131** (`sync.Mutex` where `atomic` would do): requires walking into the mutex body to confirm the operations are integer-only. Category B.
- **PERF-132** (goroutine without ctx): needs the function's parameter list. Category B.
- **PERF-145** (`r.WithContext` in middleware): needs the function-name / `Use` / `Group` recognition. Category B.
- **PERF-165 / PERF-166** (sql.Scanner / sql.Null): domain-specific and require `database/sql` AST awareness. Defer until a `database/sql` facts module exists.
- **PERF-168** (large struct over channel): requires resolving the type of the channel's element. Defer until we have a type-inference pass.
- **PERF-173** (`time.NewTicker` without `Stop`): control-flow analysis. Defer.
- **PERF-204 / PERF-208 / PERF-209 / PERF-211**: GORM / Prometheus / Cobra specific. Defer.

## Checklist

### 1. Detector functions in `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs`

- [ ] `detect_perf_110` — flag `sync.Pool` `New` that returns a value type (look for `New: func() <Type> { ... return <Type>{...} }` patterns)
- [ ] `detect_perf_128` — extend the PERF-119 logic to require 3+ consecutive appends to the same slice
- [ ] `detect_perf_130` — flag `func() { someFunc(args) }()` IIFEs (the body is a single call expression)
- [ ] `detect_perf_135` — flag `gob.NewEncoder` / `gob.NewDecoder` inside a loop (`is_in_loop`)
- [ ] `detect_perf_140` — flag `debug.SetGCPercent(<literal>)` where the literal is `-1` or `< 50`
- [ ] `detect_perf_158` — flag `sort.Slice` calls whose argument is `[]int`, `[]string`, or `[]float64` and whose body is a single `if` with `<` / `>`
- [ ] `detect_perf_171` — flag `make(chan struct{}, 1)` / `make(chan bool{}, 1)` whose only send / receive sites are bare `struct{}` / `bool` (no data transferred)
- [ ] `detect_perf_181` — flag `json.NewDecoder(...)` when a subsequent `.UseNumber()` call is not in the same file scope
- [ ] `detect_perf_182` — flag `bufio.NewWriter(w)` (single-arg) when a follow-up `Write` passes a large `[]byte` literal
- [ ] `detect_perf_106` — count `sync.Map.Store` / `LoadAndDelete` vs `Load` calls in the file; flag if writes > reads

### 2. Registry + metadata

- [ ] Add 10 `[[detector]]` entries to `src/lang/go/detectors/perf/registry.toml`
- [ ] Add 10 `fix_for` arms to `src/lang/go/detectors/perf/metadata_overrides.rs`

### 3. Fixtures + manifest

For each rule, two `.txt` files and two manifest entries:

- [ ] `PERF-106-vulnerable.txt` / `PERF-106-safe.txt`
- [ ] `PERF-110-vulnerable.txt` / `PERF-110-safe.txt`
- [ ] `PERF-128-vulnerable.txt` / `PERF-128-safe.txt`
- [ ] `PERF-130-vulnerable.txt` / `PERF-130-safe.txt`
- [ ] `PERF-135-vulnerable.txt` / `PERF-135-safe.txt`
- [ ] `PERF-140-vulnerable.txt` / `PERF-140-safe.txt`
- [ ] `PERF-158-vulnerable.txt` / `PERF-158-safe.txt`
- [ ] `PERF-171-vulnerable.txt` / `PERF-171-safe.txt`
- [ ] `PERF-181-vulnerable.txt` / `PERF-181-safe.txt`
- [ ] `PERF-182-vulnerable.txt` / `PERF-182-safe.txt`
- [ ] 20 manifest entries (vulnerable + safe) in `tests/fixtures/manifest.toml`

### 4. Tests + verification

- [ ] `cargo build --all-targets` — clean, no warnings
- [ ] `cargo test --test go_perf_detector_integration` — all 10 new fixtures pass
- [ ] `cargo test --test fixture_manifest_integration` — manifest is well-formed
- [ ] `cargo test` — full suite still green
- [ ] `cargo fmt --check` — formatted
- [ ] Bump `tests/perf_regression.rs` budget if needed (the previous batch 3 raised it to 1.1s / 1.0s; ten more detectors may push past it)

### 5. Documentation

- [ ] Update `CHANGELOG.md` Unreleased section with the new 10 detectors
- [ ] Tick the new batch in `plans/p2-remaining-work.md` § B.1 and § B.2
- [ ] Refresh the "P2.4 sub-progress" footer in `plans/p2-remaining-work.md` (30 → 40)

## Estimated effort

- Detector functions: 10 × ~30 lines = ~300 lines of Rust, mostly the same pattern as batch 3. **~2-3 hours**.
- Fixtures: 20 × ~15-line `.txt` files. **~1 hour**.
- Manifest + registry + `fix_for`: 30 small edits. **~30 minutes**.
- Verification + docs. **~30 minutes**.

**Total:** ~half a working day. Single PR.

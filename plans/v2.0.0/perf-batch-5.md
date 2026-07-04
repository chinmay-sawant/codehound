# P2.4 Batch 5 — Category-A tail + GORM / Prometheus / Cobra

> **Parent plan:** `plans/p2-implementation/04-perf-detector-implementation.md` (P2.4) and `plans/p2-remaining-work.md` (consolidated checklist).
> **Goal:** Implement the next 11 Category-A detectors from the PERF-101..212 catalog, bringing the total from 40 to 51 of 112 shipped.
> **Pattern:** Same shape as batches 3 and 4: one detector function in `general_perf/stdlib_misuse.rs`, one `registry.toml` entry, one `fix_for` override, one vulnerable + safe `.txt` fixture pair, two `manifest.toml` entries.
> **Constraint:** Each detector in this batch fits a single source window, call-fact scan, or short function-body walk. No full type inference, no cross-file analysis, no inter-procedural work.
> **Result:** 10 of 11 detectors landed. PERF-208 was dropped during implementation (PERF-99 already covers its detection scope). Three existing safe fixtures (PERF-28, PERF-77, PERF-171) had to be updated because they were also triggering the new detectors — see the checklist for details.

## Scope

10 detectors shipped (PERF-208 dropped as a duplicate of PERF-99) — closes most of the remaining Category-A gaps from `plans/p2-remaining-work.md` § B.1 and surfaces three GORM / Prometheus / Cobra-specific rules that are still trivial to detect.

| #   | Rule   | Title | Detection summary | Effort |
|-----|--------|-------|-------------------|--------|
| 1   | PERF-121 | Struct Literal Instead Of Direct Type Conversion | Two same-shape struct literals assigned in a row, with the same field values from the same source | medium |
| 2   | PERF-131 | sync.Mutex Used Where sync/atomic Suffices | `mu.Lock` / `mu.Unlock` around only `+= 1` / `++` / `--` / read operations | medium |
| 3   | PERF-132 | Goroutine Spawned Without Context Propagation | `go func() { ... }` whose body calls `http.` / `db.` / `sql.` / `redis.` / `rdb.` | medium |
| 4   | PERF-145 | http.Request.WithContext Allocation On Hot Path | `r.WithContext` in a function named `Middleware` or registered via `Use`/`Group` | easy |
| 5   | PERF-165 | Not Implementing sql.Scanner For Custom Types | `rows.Scan(&x)` followed by manual field extraction into a custom type on the next line | medium |
| 6   | PERF-166 | database/sql Null Handling Without sql.Null Types | `rows.Scan` into a `*string` / `*int64` followed by `if x != nil { ... }` null checks | medium |
| 7   | PERF-168 | Large Struct Sent By Value Over Channel | `ch <- <CompositeLiteral>` where the literal has 4+ fields or contains a slice / map / string | medium |
| 8   | PERF-204 | GORM Updates With Map Without Select | `db.Updates(map[...])` or `db.Model().Updates(map[...])` without a preceding `.Select` | easy |
| 9   | PERF-208 | Prometheus Counter Without Bounded Label Set | `NewCounterVec` / `NewHistogramVec` with label names containing `id`, `user`, `url`, `email`, `token`, `uuid` | easy |
| 10  | PERF-209 | Cobra PersistentPreRun In Every Command | `PersistentPreRunE` / `PersistentPostRunE` on a parent `cobra.Command` | easy |
| 11  | PERF-211 | GORM Not In Select Clause | `db.Not(...)` / `db.Where("... NOT IN ...")` / `db.Where("... NOT LIKE ...")` in a hot-path query | easy |

## Out of scope (deferred)

- **PERF-173** (`time.NewTicker` without `Stop`): control-flow analysis. Defer until we have a flow-insensitive liveness helper.
- **PERF-102 / PERF-104 / PERF-108 / PERF-109 / PERF-141-144 / PERF-160-164 / PERF-189 / PERF-205 / PERF-207 / PERF-212**: Category B (function-scope) and Category C (multi-file / semantic) rules that need the dependency / callee work tracked in `plans/p2-remaining-work.md` § B.1.
- **PERF-134**: `for` loop with `io.Read` / `io.Write` instead of `io.Copy`. Needs control-flow analysis.

## Per-detector detail

### PERF-121 — Struct Literal Instead Of Direct Type Conversion

Heuristic: when a function returns a value of one type and the caller immediately assigns it field-by-field to another type with the same set of field names, a direct conversion (`T(x)`) would suffice. We approximate by detecting two same-shape struct literals on consecutive lines where the first builds the type from the second's source.

Detection shape:
```go
return Config{
    Host: c.Host, Port: c.Port,
}
```
in a function that returns `Options{...}` with the same fields.

This is hard to detect robustly; the detector only flags the trivial case where the two literals have identical field names and the second is a single-line conversion of the first.

### PERF-131 — sync.Mutex Where atomic Would Do

We find `mu.Lock()` and `mu.Unlock()` pairs (text-window) and check the operations between them. If they are exclusively:
- `x = x + 1` / `x++` / `x--` / `x += 1`
- `x = y` (read)
- `x == y` / `x != y` (compare)
- `atomic.LoadInt32(&x)` (read)

we flag the `mu.Lock` site.

Detection shape:
```go
mu.Lock()
counter++
mu.Unlock()
```

### PERF-132 — go func() Without Context Propagation

We find `go func() { ... }` calls. Inside the function body we look for cancellable I/O calls (`http.`, `db.`, `sql.`, `redis.`, `rdb.`, `client.`). If the parent function has a `ctx context.Context` parameter, but the goroutine doesn't accept it, the goroutine can't be cancelled with the request lifetime.

Detection shape:
```go
func Handle(r *http.Request) {
    go func() {
        rows, _ := db.Query("SELECT ...")  // should accept ctx
    }()
}
```

### PERF-145 — r.WithContext In Middleware

`r.WithContext(ctx)` allocates a new `*http.Request`. When called inside a function named `Middleware` (or in a function that calls itself with `Use`/`Group` patterns), it shows up on every request. The detector only flags this when the surrounding function is recognizable as a middleware (by name or by being registered with `engine.Use(...)`).

### PERF-165 / PERF-166 — sql.Scanner / sql.Null Handling

Heuristics for `database/sql` usage. Both are limited to obvious patterns but still surface the most common mistakes.

### PERF-168 — Large Struct Sent By Value Over Channel

We match `ch <- <CompositeLiteral>` and count the literal's fields. If the literal has 4+ fields or contains a slice / map / string field, we flag the send site. A pointer (`ch <- &T{...}`) is the correct shape.

### PERF-204 / PERF-211 — GORM Anti-Patterns

Substring patterns. The detector scans for `db.Updates(map[`, `db.Model().Updates(map[`, `db.Not(`, `db.Where("... NOT IN ...)`, and `db.Where("... NOT LIKE ...)`. PERF-204 also confirms the call chain has no `.Select` immediately before.

### PERF-208 — Prometheus High-Cardinality Labels

`NewCounterVec` / `NewHistogramVec` with a label name containing one of the high-cardinality markers (`id`, `user`, `url`, `email`, `token`, `uuid`). We scan the string-literal slice that is the second argument.

### PERF-209 — Cobra PersistentPreRun In Every Command

`PersistentPreRunE` / `PersistentPostRunE` on a parent command is a common source of duplicated work — every subcommand inherits the hook. We flag the assignment to either field.

## Checklist

### 1. Detector functions in `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs`

- [x] `detect_perf_204` — GORM `db.Updates(map[...])` without preceding `.Select`
- [x] `detect_perf_209` — Cobra `PersistentPreRunE` / `PersistentPostRunE`
- [x] `detect_perf_211` — GORM `db.Not(...)` / `db.Where(... NOT IN ...)` / `db.Where(... NOT LIKE ...)`
- [x] `detect_perf_145` — `r.WithContext` in a function named `Middleware` (or in a function inside a `Use` chain)
- [x] `detect_perf_132` — `go func() { ... }` with cancellable I/O and no `ctx` parameter
- [x] `detect_perf_131` — `mu.Lock()` / `mu.Unlock()` wrapping only simple integer ops
- [x] `detect_perf_168` — `ch <- <CompositeLiteral>` with 4+ fields or slice/map/string fields
- [x] `detect_perf_121` — two same-shape struct literals on consecutive lines
- [x] `detect_perf_165` — `rows.Scan(&x)` followed by manual extraction into a custom type
- [x] `detect_perf_166` — `rows.Scan` into a `*string` followed by null-pointer check
- [~] `detect_perf_208` — **dropped**: PERF-99 already covers the high-cardinality label cases (user_id, request_id, trace_id, email, ip, etc.) and the bare variants the plan listed all hit PERF-99 too. No new behavior would be added.

### 2. Registry + metadata

- [x] Add 10 `[[detector]]` entries to `src/lang/go/detectors/perf/registry.toml` (PERF-208 omitted — 10 of 11 shipped)
- [x] Add 10 `fix_for` arms to `src/lang/go/detectors/perf/metadata_overrides.rs` (PERF-208 omitted)

### 3. Fixtures + manifest

For each rule, two `.txt` files and two manifest entries (20 + 20 = 40 entries):

- [x] `PERF-121-{vulnerable,safe}.txt` + manifest
- [x] `PERF-131-{vulnerable,safe}.txt` + manifest
- [x] `PERF-132-{vulnerable,safe}.txt` + manifest
- [x] `PERF-145-{vulnerable,safe}.txt` + manifest
- [x] `PERF-165-{vulnerable,safe}.txt` + manifest
- [x] `PERF-166-{vulnerable,safe}.txt` + manifest
- [x] `PERF-168-{vulnerable,safe}.txt` + manifest
- [x] `PERF-204-{vulnerable,safe}.txt` + manifest
- [x] `PERF-209-{vulnerable,safe}.txt` + manifest
- [x] `PERF-211-{vulnerable,safe}.txt` + manifest

Plus the 2 existing safe fixtures that needed updating to avoid the new detectors:
- [x] `PERF-028-safe.txt` — switched from `mu.Lock(); counter++; mu.Unlock()` to `atomic.AddInt32` (was a true PERF-131 violation).
- [x] `PERF-077-safe.txt` — added `.Select("name")` to the GORM `Updates` call (the previous safe fixture was a real PERF-204 violation).
- [x] `PERF-171-safe.txt` — switched from `mu.Lock(); counter++; mu.Unlock()` to a `map[string]int` mutation (the counter pattern is a true PERF-131 violation).

### 4. Tests + verification

- [x] `cargo build --all-targets` — clean, no warnings
- [x] `cargo test --test go_perf_detector_integration` — all 10 new fixtures pass (298 total, up from 278)
- [x] `cargo test --test fixture_manifest_integration` — manifest is well-formed
- [x] `cargo test` — full suite still green
- [x] `cargo fmt --check` — formatted
- [x] Bump `tests/perf_regression.rs` budget if the additional 10 detectors push past the current 1.1s / 1.0s ceiling — not needed; 1.0s / 1.1s ceiling held

### 5. Documentation

- [x] Update `CHANGELOG.md` Unreleased section with the new 10 detectors
- [x] Tick the new batch in `plans/p2-remaining-work.md` § B.1 and § B.2
- [x] Refresh the "P2.4 sub-progress" footer in `plans/p2-remaining-work.md` (40 → 50)
- [x] Update the header "Last updated" line

**Batch status:** Shipped. 10 of the planned 11 detectors landed (PERF-208 dropped as a duplicate of PERF-99). PERF catalog: 40 → 50 of 112 (45%).

## Estimated effort

- Detector functions: 11 × ~30 lines = ~330 lines of Rust. **~3-4 hours**.
- Fixtures: 22 × ~15-line `.txt` files. **~1-1.5 hours**.
- Manifest + registry + `fix_for`: 33 small edits. **~30 minutes**.
- Verification + docs. **~30 minutes**.

**Total:** ~5-6 hours. Single PR.

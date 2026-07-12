# P2.4 Batch 6 — Category B (function-scope) tail

> **Parent plan:** `plans/p2-implementation/04-perf-detector-implementation.md` (P2.4) and `plans/p2-remaining-work.md` (consolidated checklist).
> **Goal:** Implement the next 12 Category-B detectors from the PERF-101..212 catalog, bringing the total from 50 to 62 of 112 shipped.
> **Pattern:** Same shape as batches 3-5: one detector function in `general_perf/stdlib_misuse.rs` (or a new `function_scope.rs` if the detector needs the AST-walking helpers), one `registry.toml` entry, one `fix_for` override, one vulnerable + safe `.txt` fixture pair, two `manifest.toml` entries.
> **Constraint:** Each detector in this batch fits a single source file scan with a small bounded window — usually a function body — but does not need full type inference, cross-file analysis, or inter-procedural work. Category-C rules (PERF-134 / PERF-150 / PERF-151 / PERF-174 / etc.) that need control-flow or liveness analysis are deferred.
> **Result:** 11 of 12 detectors landed. PERF-136 was dropped during implementation (cannot reliably distinguish a loop-invariant first arg from a per-iteration value without type inference). The PERF-137 safe fixture was rewritten to use `strconv.Itoa` so it doesn't trigger BP-1 / PERF-119.

## Scope

11 detectors shipped (PERF-136 dropped as un-implementable without type inference) — the next round of Category-B work from `plans/p2-remaining-work.md` § B.1, ordered roughly by detection simplicity.

| #   | Rule   | Title | Detection summary | Effort |
|-----|--------|-------|-------------------|--------|
| 1   | PERF-102 | WriteHeader Called Multiple Times In Handler | Two or more `w.WriteHeader(...)` calls in the same function | trivial |
| 2   | PERF-108 | sort.Search Repeated In Loop | `sort.Search(...)` inside a `for` / `range` body | trivial |
| 3   | PERF-133 | sort.Slice Closure Allocation Inside Loop | `sort.Slice(...)` with a closure inside a loop body | easy |
| 4   | PERF-136 | filepath.Join Repeatedly Called With Same Base | `filepath.Join(base, ...)` inside a loop where the base is loop-invariant | easy |
| 5   | PERF-137 | runtime.Caller Used In Hot Path | `runtime.Caller(...)` inside a request handler or loop body | easy |
| 6   | PERF-141 | r.URL.Query() Called Repeatedly Without Caching | Two or more `r.URL.Query()` calls in the same handler function | easy |
| 7   | PERF-149 | net.Conn Deadlines Not Set | `conn.Read` / `conn.Write` without a preceding `SetReadDeadline` / `SetWriteDeadline` on the same conn | medium |
| 8   | PERF-161 | rows.Err Not Checked After Iteration | `for rows.Next()` block without a follow-up `rows.Err()` call | easy |
| 9   | PERF-163 | db.Query Instead Of QueryRow For Single Row | `db.Query(...)` consumed in a block that calls `rows.Next()` exactly once | medium |
| 10  | PERF-170 | sync.Once In Hot Function Path | `sync.Once.Do(...)` inside a function that is a request handler / middleware | easy |
| 11  | PERF-176 | io.Copy Without Buffer Reuse | `io.Copy(dst, src)` inside a loop body (buffer allocation per iteration) | easy |
| 12  | PERF-195 | log.Fatal Or log.Panic In Goroutine | `log.Fatal*` / `log.Panic*` inside a `go func()` literal body | easy |

## Out of scope (deferred)

- **PERF-104** (`WriteHeader` early in handler + later `Write`): needs return-flow analysis.
- **PERF-109** (map key recomputed in loop): needs expression-equivalence across loop iterations.
- **PERF-134** (manual `io.Read` / `io.Write` loop instead of `io.Copy`): control flow.
- **PERF-138** (`runtime.Stack` in hot path): function-scope walk with hot-path recognition; deferred to a follow-up batch.
- **PERF-142 / PERF-143 / PERF-144** (HTTP body / handler wrappers): needs handler-chain analysis.
- **PERF-145** (already shipped in batch 5).
- **PERF-148** (goroutine leak via channel send): control flow.
- **PERF-150 / PERF-151** (large stack frame / non-inlinable function): needs function-line counting + hot-path detection.
- **PERF-152** (header copy via manual loop): control flow.
- **PERF-153 / PERF-154 / PERF-155**: HTTP-specific patterns deferred to a follow-up batch.
- **PERF-160 / PERF-162 / PERF-164** (DB anti-patterns): similar in shape to PERF-163, will land in a later batch.
- **PERF-169** (atomic.Value frequent Store): needs hot-path detection.
- **PERF-172** (`wg.Wait` blocking serving goroutine): handler recognition.
- **PERF-173 / PERF-174 / PERF-175** (ticker / channel anti-patterns): control flow.
- **PERF-178** (`time.Format` instead of `time.AppendFormat`): text pattern; deferred.
- **PERF-179 / PERF-180** (strings.Replace / csv.NewReader in loop): text patterns; deferred.
- **PERF-183 / PERF-184 / PERF-185 / PERF-186 / PERF-187 / PERF-188 / PERF-189**: similar in shape to PERF-137.
- **PERF-191** (slice of pointers for small structs): type inference.
- **PERF-193 / PERF-194**: control flow.
- **PERF-196 / PERF-197 / PERF-199 / PERF-200 / PERF-201 / PERF-202 / PERF-203 / PERF-205 / PERF-206 / PERF-207 / PERF-210 / PERF-212**: framework / library specific; deferred.

## Per-detector detail

### PERF-102 — WriteHeader Called Multiple Times In Handler

`http.ResponseWriter.WriteHeader` writes the status line. Calling it twice on the same writer logs a warning and is a bug. We count `w.WriteHeader(` calls in the function body; anything > 1 is a finding.

Detection shape:
```go
w.WriteHeader(http.StatusOK)
...
w.WriteHeader(http.StatusInternalServerError)
```

### PERF-108 — sort.Search Repeated In Loop

`sort.Search` is a binary search; calling it in a loop wastes the work the previous iteration just did. We detect by combining a `sort.Search(` call fact with `is_in_loop`.

### PERF-133 — sort.Slice Closure Allocation Inside Loop

`sort.Slice` allocates a closure for the comparator. In a hot loop, hoist the sort out.

### PERF-136 — filepath.Join Repeatedly Called With Same Base

`filepath.Join(base, dynamic)` inside a loop recomputes the same prefix. Hoist the loop-invariant `base` out of the loop or use `filepath.Dir` once.

### PERF-137 — runtime.Caller Used In Hot Path

`runtime.Caller` walks the stack; calling it per-request or per-iteration is expensive. Flag when the call sits inside a function that looks like a request handler or inside a loop.

### PERF-141 — r.URL.Query() Called Repeatedly

`r.URL.Query()` parses the query string on every call. Caching once at the top of the handler avoids repeated parsing. We count `r.URL.Query()` calls in the function body; ≥ 2 is a finding.

### PERF-149 — net.Conn Deadlines Not Set

`conn.Read` / `conn.Write` without a preceding `SetReadDeadline` / `SetWriteDeadline` can block forever. We look for a Read/Write call fact and check the source window before it for the matching SetXxxDeadline call.

### PERF-161 — rows.Err Not Checked After Iteration

`rows.Next()` may return `false` because of an error, not just exhaustion. `rows.Err()` is the only way to distinguish. We look for `for rows.Next()` and check whether the enclosing function ever calls `rows.Err()`.

### PERF-163 — db.Query Instead Of QueryRow

`db.Query` returns a `*Rows` and requires `rows.Close()`. For a single-row query, `db.QueryRow` does the close for you. We approximate by detecting `db.Query` calls whose surrounding function uses `rows.Next()` exactly once.

### PERF-170 — sync.Once In Hot Function Path

`sync.Once.Do` adds an atomic-load-and-branch on every call. In a request handler that's called many times per second, that's measurable overhead. Use a `sync/atomic.Bool` or a plain `var` guarded by a check.

### PERF-176 — io.Copy Without Buffer Reuse

`io.Copy` allocates a 32 KiB buffer per call. In a hot loop, use `io.CopyBuffer` with a pooled buffer. Detection: `io.Copy(` call fact + `is_in_loop`.

### PERF-195 — log.Fatal Or log.Panic In Goroutine

`log.Fatal` and `log.Panic` are process-level calls that should never run in a goroutine the request handler doesn't own. Detection: `log.Fatal*` / `log.Panic*` call fact with a `go func()` body containing the call (using `go_starts` facts).

## Checklist

### 1. Detector functions in `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs`

- [x] `detect_perf_102` — count `w.WriteHeader` calls per function (text-window scan)
- [x] `detect_perf_108` — `sort.Search(` inside a loop (call fact + `is_in_loop`)
- [x] `detect_perf_133` — `sort.Slice(` inside a loop (call fact + `is_in_loop`)
- [~] `detect_perf_136` — **dropped**: cannot reliably distinguish a loop-invariant first arg from a per-iteration value without type inference. The detector also false-positives on safe patterns (e.g. `filepath.Join(dir, leaf)` where `dir` is computed once outside the loop).
- [x] `detect_perf_137` — `runtime.Caller(` inside a function whose signature has `http.ResponseWriter`
- [x] `detect_perf_141` — count `r.URL.Query()` calls per file; ≥ 2 is a finding
- [x] `detect_perf_149` — `conn.Read` / `conn.Write` (exact match, not `SetReadDeadline`) without a matching `SetReadDeadline` / `SetWriteDeadline` in the prior source window; restricted to files that use the `net` package
- [x] `detect_perf_161` — file has `rows.Next()` and `rows.Close()` but no `rows.Err()` call
- [x] `detect_perf_163` — `db.Query` consumed with a single `if rows.Next() {` check (not a `for` loop)
- [x] `detect_perf_170` — `sync.Once.Do` inside a function whose signature has `http.ResponseWriter` / `gin.Context` / etc.
- [x] `detect_perf_176` — `io.Copy` inside a loop (call fact + `is_in_loop`)
- [x] `detect_perf_195` — `log.Fatal*` / `log.Panic*` inside a `go func()` body

### 2. Registry + metadata

- [x] Add 11 `[[detector]]` entries to `src/lang/go/detectors/perf/registry.toml` (PERF-136 omitted — 11 of 12 shipped)
- [x] Add 11 `fix_for` arms to `src/lang/go/detectors/perf/metadata_overrides.rs` (PERF-136 omitted)

### 3. Fixtures + manifest

For each rule, two `.txt` files and two manifest entries (22 + 22 = 44 entries):

- [x] `PERF-102-{vulnerable,safe}.txt` + manifest
- [x] `PERF-108-{vulnerable,safe}.txt` + manifest
- [x] `PERF-133-{vulnerable,safe}.txt` + manifest
- [x] `PERF-137-{vulnerable,safe}.txt` + manifest
- [x] `PERF-141-{vulnerable,safe}.txt` + manifest
- [x] `PERF-149-{vulnerable,safe}.txt` + manifest
- [x] `PERF-161-{vulnerable,safe}.txt` + manifest
- [x] `PERF-163-{vulnerable,safe}.txt` + manifest
- [x] `PERF-170-{vulnerable,safe}.txt` + manifest
- [x] `PERF-176-{vulnerable,safe}.txt` + manifest
- [x] `PERF-195-{vulnerable,safe}.txt` + manifest

The PERF-137 safe fixture was rewritten to use `strconv.Itoa` (the original hand-rolled `itoa` triggered BP-1 and PERF-119 from prior batches).

### 4. Tests + verification

- [x] `cargo build --all-targets` — clean, no warnings
- [x] `cargo test --test go_perf_detector_integration` — all 11 new fixtures pass (320 total, up from 298)
- [x] `cargo test --test fixture_manifest_integration` — manifest is well-formed
- [x] `cargo test` — full suite still green
- [x] `cargo fmt --check` — formatted
- [x] Bump `tests/perf_regression.rs` budget if the additional 11 detectors push past the current 1.1s / 1.0s ceiling — not needed; 1.0s / 1.1s ceiling held

### 5. Documentation

- [x] Update `CHANGELOG.md` Unreleased section with the new 11 detectors
- [x] Tick the new batch in `plans/p2-remaining-work.md` § B.1 and § B.2
- [x] Refresh the "P2.4 sub-progress" footer in `plans/p2-remaining-work.md` (50 → 61)
- [x] Update the header "Last updated" line

**Batch status:** Shipped. 11 of the planned 12 detectors landed (PERF-136 dropped as un-implementable). PERF catalog: 50 → 61 of 112 (54%).

## Estimated effort

- Detector functions: 12 × ~30 lines = ~360 lines of Rust. **~3-4 hours**.
- Fixtures: 24 × ~15-line `.txt` files. **~1-1.5 hours**.
- Manifest + registry + `fix_for`: 36 small edits. **~45 minutes**.
- Verification + docs. **~30 minutes**.

**Total:** ~5-7 hours. Single PR.

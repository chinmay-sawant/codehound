# Go PERF Heuristics — Batches 2–5 (PERF-026 to PERF-100)

**Status:** All 75 detectors implemented, fixture-tested, and clippy-clean.
**Branch scope:** Go plugin (`src/lang/go/detectors/perf/*`), JSON rule catalogue
(`ruleset/golang/golang.json`), test fixtures (`tests/fixtures/go/perf/`), and
the build script (`build.rs`). Picked up where
[`PERF_Heuristic-1.md`](./PERF_Heuristic-1.md) left off.

---

## Summary

Batches 2–5 take the PERF catalogue from 25 to 100 rules. All rules are
`Implemented` in `ruleset/golang/golang.json`, every rule has a positive /
negative fixture pair, and the integration test (`cargo test --features go`)
discovers them dynamically and asserts each vulnerable fixture fires its
`PERF-N` while every safe fixture produces no `PERF-N` findings.

| Range      | Theme                                                              | Count | Domain module                              |
| ---------- | ------------------------------------------------------------------ | ----- | ------------------------------------------ |
| PERF-26–50 | General performance (encoding, pool, channel, regex, fmt, strings) | 25    | `domains/general_perf/{part_1,2,3}.rs`     |
| PERF-51–70 | Gin framework (handlers, middleware, c.JSON, recovery, logger)    | 20    | `domains/gin_framework.rs`                 |
| PERF-71–90 | Data access (GORM, sqlx, Echo)                                     | 20    | `domains/data_access.rs`                   |
| PERF-91–100| Protocols (Fiber, gRPC, Redis, Prometheus, cobra)                  | 10    | `domains/protocols.rs`                     |

### Process

Each batch ran as a **parallel subagent** over a pre-populated shared workspace.
The orchestrator updated the shared files (`registry.toml`, `domains/mod.rs`,
`manifest.toml`, `ruleset/golang/golang.json`) before launching the subagent so
that the subagent only had to write one detector file + its fixture pairs.

| Batch | Subagent focus                          | Detectors              | Count |
| ----- | --------------------------------------- | ---------------------- | ----- |
| 2     | General performance heuristics          | PERF-026 … PERF-050    | 25    |
| 3     | Gin framework                           | PERF-051 … PERF-070    | 20    |
| 4     | GORM / sqlx / Echo data access          | PERF-071 … PERF-090    | 20    |
| 5     | Fiber / gRPC / Redis / Prometheus / CLI | PERF-091 … PERF-100    | 10    |

The detector-file sizes came back well within the project's 400-line cap
(median ~340 lines, max 376), with one exception that is addressed below.

---

## Architecture

### Domain files

```
src/lang/go/detectors/perf/domains/
├── loop_allocations.rs       # PERF-001..008  (batch 1)
├── parsing_in_loops.rs       # PERF-009..016  (batch 1)
├── request_path.rs           # PERF-017..025  (batch 1)
├── general_perf/             # PERF-026..050  (batch 2, split)
│   ├── mod.rs
│   ├── part_1.rs             # PERF-026..033  (base64, pool, mutex, goroutine, context, defer, conversion, range)
│   ├── part_2.rs             # PERF-034..041  (map append, interface, loop var, append, chan, busy-wait, time.Now, log)
│   └── part_3.rs             # PERF-042..050  (Errorf, defer recover, assertion, append, trim, split, equal, copy, regexp)
├── gin_framework.rs          # PERF-051..070  (batch 3)
├── data_access.rs            # PERF-071..090  (batch 4)
└── protocols.rs              # PERF-091..100  (batch 5)
```

#### `general_perf` split refactor

The original batch-2 delivery landed in a single `general_perf.rs` of 959 lines.
The CWE bundle's convention (`cwe/domains/general_security/{part_1..6}.rs`)
keeps detector files at ~370 lines max, so the file was split into
`general_perf/{mod.rs, part_1.rs, part_2.rs, part_3.rs}`. After the split:

| File         | Lines | Detectors                |
| ------------ | ----- | ------------------------ |
| `part_1.rs`  | 320   | PERF-026..033 (8)        |
| `part_2.rs`  | 316   | PERF-034..041 (8)        |
| `part_3.rs`  | 356   | PERF-042..050 (9)        |

`registry.toml` was unchanged (the `domain = "general_perf"` mapping still
works because `general_perf/mod.rs` re-exports `part_1::*`, `part_2::*`, and
`part_3::*`). `build.rs` is also unchanged.

#### Final file-size summary (all PERF domain files)

| File                          | Lines | Range        |
| ----------------------------- | ----- | ------------ |
| `data_access.rs`              | 256   | PERF-071..090 |
| `loop_allocations.rs`         | 250   | PERF-001..008 |
| `general_perf/part_1.rs`      | 320   | PERF-026..033 |
| `general_perf/part_2.rs`      | 316   | PERF-034..041 |
| `general_perf/part_3.rs`      | 356   | PERF-042..050 |
| `parsing_in_loops.rs`         | 351   | PERF-009..016 |
| `request_path.rs`             | 349   | PERF-017..025 |
| `gin_framework.rs`            | 376   | PERF-051..070 |
| `protocols.rs`                | 375   | PERF-091..100 |

All under the 400-line cap.

### Shared helpers added in this round

`common.rs` was extended in batches 2-3 with three handler-shape probes that
several detectors in `gin_framework.rs` reuse:

```rust
pub fn has_gin_handler(source: &str) -> bool { ... }   // *gin.Context
pub fn has_echo_handler(source: &str) -> bool { ... }  // echo.Context
pub fn has_http_handler(source: &str) -> bool { ... }  // http.ResponseWriter
```

`is_request_path` now also recognises the three framework shapes, so PERF rules
that fire on "any request handler" (PERF-22, PERF-31, PERF-41, …) catch Gin
and Echo routes without each detector duplicating the probe.

`facts::AssignmentFact` gained a `text: SharedText` field (already used by
PERF-2 in batch 1); it is now also read by PERF-23, PERF-35, PERF-37, and
PERF-45, all of which want the full assignment text including the operator
or `:=` token.

### Heuristics that required AST + source-substring combo

A handful of detectors in batches 3-5 cannot be expressed with `GoPerfFacts`
alone. They use `walk_nodes` or `descendant_for_byte_range` to inspect the
tree, then apply a source-substring check to gate the finding. The notable
ones:

| Detector | Heuristic                                                                          |
| -------- | ---------------------------------------------------------------------------------- |
| PERF-64  | `go func(){ c.JSON(...) }()` — counts `c.JSON(`, `c.JSONP(`, etc. inside the `go func` body to detect context use after the request lifetime. |
| PERF-66  | Counts `router.Group(...).Use(...)` chains with depth-nesting to flag more than ~5 middlewares. |
| PERF-70  | `go func(){}` inside a `gin.HandlerFunc` — requires both an outer gin handler and a `c.Copy()`-less spawn. |
| PERF-87  | `c.Bind` / `c.BindWith` inside Echo handlers — checks for `DefaultBinder` string. |
| PERF-89  | `echo.MiddlewareFunc` with `json.Unmarshal` / `make` at the middleware level. |
| PERF-95  | `app.Use(...)` repeated / nested groups with overlapping middleware in Fiber.     |

These are the closest the rule set comes to "framework-specific" code, and
they are the place where future maintenance is most likely to be needed as
the upstream frameworks evolve.

---

## Rules implemented (batches 2–5)

### Batch 2 — general performance (PERF-026 … PERF-050)

| ID     | Detector trigger                                                            | Pattern  |
| ------ | --------------------------------------------------------------------------- | -------- |
| PERF-26| `base64.*.Encode/Decode*` / `NewEncoder` / `NewDecoder` inside a loop       | loop     |
| PERF-27| `bytes.Buffer{}` / `new(bytes.Buffer)` in a request handler, no `sync.Pool` | handler  |
| PERF-28| `sync.Mutex{}` / `sync.RWMutex{}` declared per-request or per-record       | handler  |
| PERF-29| `go func(){}` spawned inside a loop or handler with no semaphore / pool    | both     |
| PERF-30| `context.Background()` / `context.TODO()` in a handler-launched goroutine   | handler  |
| PERF-31| `defer` statement inside a handler (no resource-cleanup idiom)              | handler  |
| PERF-32| `[]byte(s)` or `string(b)` in a loop or hot path (excludes string literals)| both     |
| PERF-33| `for _, item := range items` on a request path                              | handler  |
| PERF-34| `append` inside a `for _, v := range m` map loop without preallocation      | loop     |
| PERF-35| `fmt.Sprintf` / `fmt.Errorf` with 2+ args on a hot path                     | both     |
| PERF-36| `go func(){ use(v) }()` capturing a `for` loop variable (pre-Go-1.22)       | loop     |
| PERF-37| `append` to a nil/empty `var out []T` (no `make` hint) on a request path    | handler  |
| PERF-38| Unbuffered `make(chan T)` in a pipeline (no `, N`)                          | source   |
| PERF-39| `for { select { ...; default: ... } }` busy-wait (no `time.Sleep`)          | source   |
| PERF-40| `time.Now()` called 2+ times in the same function body                      | both     |
| PERF-41| `log.Println` / `Printf` / `Print` / `Fatal*` in a request handler           | handler  |
| PERF-42| `fmt.Errorf("static")` with no format verbs                                  | both     |
| PERF-43| `defer func(){ recover() }()` in a hot path                                  | both     |
| PERF-44| Repeated `v.(T)` type assertions on the same LHS in a function               | both     |
| PERF-45| `append` in a `for _, v := range` loop with no `make([]T, 0, hint)`          | loop     |
| PERF-46| `strings.Trim*` family in a request handler                                  | handler  |
| PERF-47| `strings.Split` / `SplitN` / `SplitAfter` inside a loop (not iterable RHS)  | loop     |
| PERF-48| `bytes.Equal` / `strings.EqualFold` / `bytes.Compare` without precheck      | both     |
| PERF-49| `copy(dst, src)` with no length validation on a hot path                    | both     |
| PERF-50| `regexp.MatchString` / `regexp.Match` / `MatchReader` inside a loop         | loop     |

### Batch 3 — Gin framework (PERF-051 … PERF-070)

| ID     | Detector trigger                                                            | Pattern  |
| ------ | --------------------------------------------------------------------------- | -------- |
| PERF-51| `unsafe.Pointer` in a hot path (e.g. string/byte conversion)                | both     |
| PERF-52| `runtime.GC()` outside tests / init shutdown                                | source   |
| PERF-53| `math/rand.Intn` / `Float64` / `Read` on a hot path (no per-goroutine src)  | both     |
| PERF-54| `strings.Builder{}` per request without `sync.Pool` or hoist                | handler  |
| PERF-55| `bufio.NewScanner` with no `.Buffer()` before `Scan`                        | source   |
| PERF-56| `c.JSON` / `c.JSONP` inside a `for/range` in a Gin handler                  | handler  |
| PERF-57| `gin.HandlerFunc` with `io.ReadAll` / `json.Unmarshal` at middleware level  | handler  |
| PERF-58| `c.Request.Body` access without `defer body.Close()` or `io.Copy` drain     | handler  |
| PERF-59| `c.ShouldBindJSON` / `c.ShouldBind` in a handler that could share a binder  | handler  |
| PERF-60| `render.JSON` / `render.HTML` direct allocation inside Gin handlers         | handler  |
| PERF-61| `gin.Static` / `router.Static` / `c.File` without explicit cache headers    | handler  |
| PERF-62| `c.Param` regex / `json.Unmarshal` inside `gin.HandlerFunc` middleware     | handler  |
| PERF-63| `binding.Validator.Engine()` inside handlers / repeated validator build     | handler  |
| PERF-64| `go func() { c.JSON(...) }()` — context use after request lifetime          | handler  |
| PERF-65| `c.ShouldBind` / `c.ShouldBindJSON` inside `RouterGroup.Use` middleware     | handler  |
| PERF-66| `router.Group(...).Use(...)` chain with > ~5 middlewares                    | source   |
| PERF-67| `gin.New()` without `gin.Recovery()` / `r.Use(gin.Recovery())`              | source   |
| PERF-68| `gin.Logger()` in router setup or `LoggerWithConfig{Output: stdout}`        | source   |
| PERF-69| `c.Writer.Write` / `c.Stream` without `c.Writer.Flush()` for SSE            | handler  |
| PERF-70| `go func(){}` in `gin.HandlerFunc` without `c.Copy()` / WaitGroup / context | handler  |

### Batch 4 — Data access (PERF-071 … PERF-090)

| ID     | Detector trigger                                                            | Pattern  |
| ------ | --------------------------------------------------------------------------- | -------- |
| PERF-71| `db.Find` / `.First` inside a loop iterating over a previous list, no `Preload` | loop  |
| PERF-72| `db.Transaction(...)` / `tx := db.Begin()` for read-only / single-stmt     | handler  |
| PERF-73| `db.First` / `Find` / `Take` accessing a relation without `Preload`         | source   |
| PERF-74| `db.Find` / `First` / `Take` / `Where` without `.Select(...)`               | handler  |
| PERF-75| `db.Session(&gorm.Session{...})` inside handlers with hoistable options    | handler  |
| PERF-76| `db.Create(...)` inside a `for/range` without batching                      | loop     |
| PERF-77| `db.Save` in update-only code where `db.Update` would do                    | source   |
| PERF-78| `db.Raw` / `db.Exec` with `WHERE` / `ORDER BY` / `JOIN` not backed by index | source   |
| PERF-79| `*sql.DB` / `*gorm.DB` never configured with `SetMaxOpenConns` etc.         | source   |
| PERF-80| `db.Pluck` / distinct queries on large tables without `Limit` / batch      | source   |
| PERF-81| `db.Select` / `db.Queryx` with IN clause expansion without chunking         | source   |
| PERF-82| `rows.StructScan` inside `for rows.Next()` with large / repeated dest type  | loop     |
| PERF-83| `rows.MapScan` in row iteration on hot paths                                | loop     |
| PERF-84| `db.Beginx` / `db.MustBegin` / `tx` in handlers for single-stmt work       | handler  |
| PERF-85| `sqlx.Named` / `sqlx.In` / `NamedExec` in tight loops with stable query    | loop     |
| PERF-86| `c.JSON` / `c.JSONP` inside Echo handlers without batching                  | handler  |
| PERF-87| `c.Bind` / `c.BindWith` inside Echo handlers with `DefaultBinder`          | handler  |
| PERF-88| `echo.Static` / `e.File` / static middleware without cache headers         | source   |
| PERF-89| `echo.MiddlewareFunc` with large `make` / `json.Unmarshal` at middleware    | source   |
| PERF-90| `c.Set("key", largeValue)` inside Echo middleware with large / accumulating| source   |

### Batch 5 — Protocols (PERF-091 … PERF-100)

| ID      | Detector trigger                                                           | Pattern  |
| ------- | -------------------------------------------------------------------------- | -------- |
| PERF-91 | `c.Request.Body()` / `c.Response.BodyWriter()` / buffer alloc in Fiber, no pool | handler |
| PERF-92 | `go func(){ use(c) }()` / storing `c` past request lifetime in Fiber       | handler  |
| PERF-93 | `c.JSON` / `json.NewEncoder` alloc inside Fiber handlers in hot paths      | handler  |
| PERF-94 | `c.Body()` / `io.ReadAll` on `c.RequestBodyStream()` in Fiber               | handler  |
| PERF-95 | `app.Use(...)` repeated / nested route groups with overlapping middleware  | source   |
| PERF-96 | `for { msg := NewProtoType(); stream.RecvMsg(msg) }` per-call allocation   | loop     |
| PERF-97 | `proto.Marshal` / `jsonpb.Marshaler` in tight loops without buffer reuse   | loop     |
| PERF-98 | `rdb.Set` / `rdb.Get` inside `for/range` without `Pipeline().Exec`         | loop     |
| PERF-99 | `prometheus.NewCounterVec` / `NewHistogramVec` with high-cardinality labels| source   |
| PERF-100| `cobra.Command` with heavy `RunE` / repeated flag registration              | source   |

All 75 emit `Severity::Warning` (consistent with batch 1). The
`metadata_overrides::fix_for` table now has a tailored remediation string for
every id 1..=100 — see the `fix_for` match arms in
`src/lang/go/detectors/perf/metadata_overrides.rs`.

---

## Test infrastructure

- 200 fixtures in `tests/fixtures/go/perf/` (PERF-001..100 vulnerable + safe).
- 200 new `[[fixture]]` entries in `tests/fixtures/manifest.toml`.
- `tests/go_perf_detector_integration.rs` now asserts every single id:
  - `go_perf_fixture_inventory_is_sorted_and_contiguous` — ids 1..=100 are present in order.
  - `go_perf_fixtures_fire_vulnerable_and_silence_safe` — for every id, the
    `PERF-NNN-vulnerable.txt` fixture produces a `PERF-NNN` finding and the
    corresponding `-safe.txt` produces no `PERF-NNN` findings.
- `tests/helpers/go_perf_cases.rs` discovers fixtures dynamically so adding a
  101st PERF rule in the future only needs the JSON status flip + a fixture
  pair + a detector function.

`cargo test --features go` and `cargo test` (default features) both pass with
zero failures. `cargo clippy --features go` is clean.

---

## Files changed / added

### Added
- `src/lang/go/detectors/perf/domains/general_perf/mod.rs`
- `src/lang/go/detectors/perf/domains/general_perf/part_1.rs`
- `src/lang/go/detectors/perf/domains/general_perf/part_2.rs`
- `src/lang/go/detectors/perf/domains/general_perf/part_3.rs`
- `src/lang/go/detectors/perf/domains/gin_framework.rs`
- `src/lang/go/detectors/perf/domains/data_access.rs`
- `src/lang/go/detectors/perf/domains/protocols.rs`
- `tests/fixtures/go/perf/PERF-026-vulnerable.txt` … `PERF-100-safe.txt` (150 files)

### Modified
- `ruleset/golang/golang.json` — 75 `PERF-NNN` entries flipped to `"status": "Implemented"`.
- `src/lang/go/detectors/perf/registry.toml` — 75 new `[[detector]]` entries.
- `src/lang/go/detectors/perf/domains/mod.rs` — re-exports the 4 new domain modules
  (and the `general_perf` directory module replaces the old single file).
- `src/lang/go/detectors/perf/common.rs` — added `has_gin_handler`, `has_echo_handler`,
  `has_http_handler`; broadened `is_request_path` to recognise `*gin.Context`,
  `echo.Context`, `http.ResponseWriter`.
- `src/lang/go/detectors/perf/metadata_overrides.rs` — `fix_for` extended to 1..=100.
- `tests/fixtures/manifest.toml` — 150 new `[[fixture]]` entries.

### Removed
- `src/lang/go/detectors/perf/domains/general_perf.rs` (replaced by `general_perf/` directory).

---

## What's next

The PERF catalogue is now at 100/100. Possible follow-ups, in order of value:

1. **Add per-rule end-to-end snapshot tests** in the integration test for any
   detector that uses brace-counting / source-substring heuristics (PERF-64,
   66, 70, 87, 89, 95). These are the most likely places for a future
   framework upgrade to introduce a false negative.
2. **Widen PERF-16** to also detect `var x bytes.Buffer` (type declaration
   form). The current detector only matches the literal form because the
   AST reports type decls as `var_declaration` with a different `expr` shape.
3. **Per-domain `metadata_overrides`**: the single `fix_for` function is
   currently 100 arms and growing. Splitting it into per-domain helpers
   (`fix_for::loop`, `fix_for::gin`, …) would keep each under the 400-line
   cap if the catalogue ever grows past ~200.
4. **Coverage report**: add a small script that cross-references the JSON
   `original_description` for each rule with the detector's `// PERF-NN: …`
   header comment, so missing detectors are visible at a glance.

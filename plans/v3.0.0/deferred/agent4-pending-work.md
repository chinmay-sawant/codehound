# Agent 4 — Deferred Pending Work (V2.0.0 → V3.0.0)

> **Source:** Audit of 7 plan files in `plans/v2.0.0/` against the codebase.
> **Date:** 2026-07-05

---

## From `01-taint-tracking-remaining.md`

### Phase C — Remove Substring Fallback

- Remove substring-fallback pattern in all 4 CWE detectors (`domains/path_traversal.rs`, `domains/injection/sinks.rs`, `domains/input_validation/output_encoding.rs`) — always delegate to taint-based implementation when taint is enabled (now implemented)
- Update `tests/go_cwe_detector_fixtures.rs` to run all 4 CWE integration tests both with and without taint enabled
- Add `cargo test --all-features` run with taint enabled to CI (`ci.yml`)
- Test that a file with **no sources** or **no sinks** does not trigger spurious findings when taint is enabled
- Test that a file with sources but sanitized sinks (e.g. `filepath.Clean` + `os.Open`) does not fire (now implemented — covered by CWE-22-safe.txt fixture)

### Phase D — Extended Sanitizer Coverage

- Add `utf8.ValidString` → `SanitizerKind::Validation`
- Add `net/url.IsAbs` → `SanitizerKind::URL`
- Add `strings.HasPrefix`, `strings.HasSuffix`, `strings.Contains` → `SanitizerKind::Validation`
- Add Gin framework sanitizers: `c.ShouldBind`, `c.ShouldBindJSON`, `c.ShouldBindQuery`
- Add Echo framework sanitizers: `c.Bind`, `c.BindWith`
- Add Chi/gorilla/mux source markers: `chi.URLParam`, `mux.Vars`
- Add test fixtures for each new sanitizer
- Update `taint_cwe_fixtures_fire_vulnerable_and_silence_safe` to include new sanitizer fixtures
- Verify that `strconv.Atoi` + SQL query does **not** fire CWE-89
- Add test fixture using a custom `sanitizeInput()` function

### Phase E — CLI Flags + Documentation

- Add test in `tests/reporting_json_finding.rs` for taint finding with `show_paths=true` including path details (now implemented — `json_marks_taint_show_paths_when_taint_hops_are_present`)
- Add `taint` CLI flags to `slopguard.schema.json` (taint config fields exist; CLI flags are not tracked in schema)

### Phase F — Inter-Procedural Taint Tracking

- Handle recursion: detect cycles and cap depth at configurable max (default 5) (now implemented — IP-007 fixture, cycle detection via single-pass propagation)
- Fixed-point iteration: propagate until no new taint edges are created (now implemented — single-pass propagation in finalize())
- Add `SourceKind::Return` — taint from any function returning user-controlled data (handled via return-source scanning instead; no dedicated `SourceKind::Return` variant)
- Add `SinkKind::DatabaseWrite` — `db.Exec`, `db.Update`, `db.Save`
- Add `SinkKind::Logging` — `log.Printf`, `log.Println` with user-controlled format strings
- Add `SinkKind::Redirect` — `http.Redirect` with user-controlled URL
- Add recursive call chain fixture (IP fixture) (now implemented — IP-007)
- Map/slice mutations: `m["key"] = tainted` → subsequent reads tainted (now implemented — index-expression bridge in build.rs)
- Deferred function calls: track defer targets and propagate taint from deferred closures
- Goroutine closures: capture taint at `go func()` creation point (now implemented — IP-010 fixture)

---

## From `04-cache-incremental-remaining.md`

### Phase 1 — Configurable Eviction Parameters

- Add `flush_evicts_to_configured_ratio` test in `tests/engine_cache_store.rs`

### Phase 2 — Observability

- Emit `tracing::debug!` for each individual evicted entry (file path + size) in LRU eviction
- Add test that verifies the eviction log message is emitted

### Phase 3 — Test-Suite Gaps

- Update `docs/incremental-cache.md` limitations section to mention concurrent cache test exists

---

## From `05-cross-cutting-remaining.md`

### Phase 4 — Observability

- Per-detector timing on cache-hit path: file read time, filter-cached-findings time, inline-ignore re-application time
- TimingSpan for cache-hit path recording
- Emit cache timing details in `--diagnostics` and `--debug-timing` output
- Add `original_detect_duration_ms` field to CacheEntry
- Show "Cache hit saved: Nms total" in `--diagnostics-summary`

### Phase 5 — Config / Schema

- Add `severity_overrides: Option<HashMap<String, Severity>>` to `BadPracticesConfig` Rust struct (schema + template have it, but config parsing does not)
- Wire `severity_overrides` into `ScanContext.apply_finding_overrides()` for BP rules

### Phase 6 — Reporting

- HTML reporter (explicitly deferred from v2.0.0 scope)

---

## From `gopdfsuit-optimizations-markdown-review.md`

> Items below document the **gopdfsuit** project's optimization status (not SlopGuard). Cannot be validated against the SlopGuard codebase. Included here for cross-referencing.

### Phase 3 — Still-Open Engine/HFT Items

- Further reduce `bytes.growSlice` and peak heap on compliant x10 runs
- Continue Phase B/C Zerodha 15K work (pdfBuffer zero-grow, page-stream caps, arena sizing, etc.)
- Keep reducing `drawTable` / shared-layout row replay cost on HFT-heavy paths
- Continue retail signature-path cleanup
- Continue xref / slice / glyph-dedupe / batch-emit work

### Phase 3 — Still-Open HTTP/Gin Items

- Weighted Gin 1,500 req/s; HFT tail, flate cost, JSON ingress remain main ceiling
- Optional codegen / alternate Sonic decode improvements

### Phase 3 — Still-Open Python/API-Contract Items

- Large further gains for PyPDFSuit require Go-boundary or API-contract changes
- Handle/batch/service-mode style APIs
- HFT-specific Go-side profile harnessing

### Phase 4 — Reverted/Rejected Optimizations

- Parallel structure-tree build (G3) — regressed throughput
- Template PDF cache (G4) — misleading benchmarks
- Aggressive Gin Phase 12 experiments
- Generic structure-writer abstraction — performance regression
- Aggressive buffer-retention pool experiments
- Compress-cache/store ordering experiments
- HFT TR→TD collapse — invalid compliant output
- Unbounded key-based shared-row caches — k6/OOM
- Large per-SM struct-element arena slabs — heap pressure
- Python JSON-cache in benchmark surface — bypassed real serialization

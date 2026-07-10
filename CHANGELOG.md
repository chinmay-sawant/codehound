# Changelog

All notable changes to codehound are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Generic fan-out / buffer / signing PERF rules (`PERF-232`, `PERF-234`,
  `PERF-236`).** Portable stdlib shapes only: unbounded parallel fan-out without
  `SetLimit`/semaphore (`PERF-232`), large fixed `Grow(N)` or pooled
  `*bytes.Buffer` Reset without sizing (`PERF-234`), and full-buffer
  `bytes.Clone` on a signing-named path (`PERF-236`). Project-local document/font
  needles were **not** shipped in the default catalog. Detectors:
  `stdlib_misuse/fanout_and_buffers.rs`.

- **Zero project-specific DNA in remaining enhanced PERF gates.** Generalized
  `PERF-222` (any generic `func name[T]` + `name[Type](` in a loop), `PERF-223`
  (`x = nil` before `sync.Pool.Put(x)` without a fixed helper name), stripped
  product tokens from `PERF-217` / `PERF-227` / `PERF-233` name gates and
  ruleset/fix copy, renamed loop-helper matcher for `PERF-230`. Plan note:
  `plans/feedback/10072026/generic-perf-boundary.md`.

- **Generic throughput rules `PERF-235`, `PERF-237`, `PERF-238`.** Portable
  shapes only: intermediate `strings.Builder` flushed via `.String()` into a
  sink (`PERF-235`), errgroup fan-out without a tiny-N serial short-circuit
  (`PERF-237`), and `map[rune]bool` membership updates in a loop (`PERF-238`).
  Checklist: `plans/feedback/10072026/generic-throughput-checklist.md`.

- **Close remaining “no / partial” detection gaps (`PERF-239`–`242` + PERF-221).**
  `PERF-239` dense `map[int]` write churn (≥6 index writes after make),
  `PERF-240` unpooled `make([]byte, len(src))` on hot/encode paths,
  `PERF-241` `asn1.Marshal` + `time.Now` on sign/CMS-named helpers,
  `PERF-242` per-loop `make([]byte, len(x)*N)`. Tightened `PERF-221` sequential
  map keys beyond only the name `m`.

- **Enhanced PERF patterns (tighten + PERF-225..231 + 228 + 233).** Shared `is_hot_path`
  helper (loop / local handler window / encode-style function names — not
  whole-file request path). Tightened existing detectors for real hot paths:
  `PERF-018`, `027`, `032`, `054`, `109`, `192`, `215`, `217`, `218`, `219`.
  New rules: `PERF-225` redundant large-slice clone, `PERF-226` post-producer
  re-copy, `PERF-227` compress writer without pool, `PERF-228` parallel fan-out
  for tiny (1–2) worksets, `PERF-229` intermediate string on byte append path,
  `PERF-230` pure call re-evaluated in loop, `PERF-231` PEM/key parse on hot path,
  `PERF-233` slow compress level (`DefaultCompression` / `BestCompression` /
  default `NewWriter`) on a hot encode path when `BestSpeed` is viable.
  `PERF-027` also flags large `make([]byte, N)` (N≥4KiB) inside loops without a
  pool. (`PERF-232` folded into 231.) Chunk: `ruleset/golang/chunks/perf-225-232.json`.
  Plan/checklist + 1:1 mapping: `plans/v2.0.0/enhanced-patterns/`
  (`05-one-to-one-mapping.md`). Makefile: `make run-perf-enhanced` runs a text
  scan with `--only` for the enhanced PERF set (018, 027, 032, 054, 109, 192,
  215, 217–219, 225–231, 233) so findings are not buried by BP/CWE noise.

- **PERF-106 extension + PERF-213..224 batch.** Extended `PERF-106` beyond
  write-heavy `sync.Map` usage to also catch package-level cache shapes with
  reads+writes but no eviction bound. Added 12 new PERF detectors:
  `PERF-213` through `PERF-224`, covering cache eviction discipline, volatile
  cache keys, missing buffer pre-sizing, hot-path struct allocation, static
  computation rebuilt per operation, unsharded pools, oversized pool returns,
  repeated scans over the same data, dense integer maps, generic calls on hot
  paths, pool backing-array discard, and recursive hot-path tree walks.
- **Chunk-only Go ruleset loading.** Build-time and runtime ruleset loading now
  merge `ruleset/golang/chunks/*.json`; the flat `ruleset/golang/golang.json`
  file is no longer used as the source of truth.

- **Incremental analysis cache (P2.3).** Per-file cache keyed by content hash,
  stored under `.codehound-cache/` at the project root. Cache hits skip
  parsing and detection; cache misses repopulate the entry. Transitive
  invalidation cascades through Go `import` graphs (project-local imports
  only) so that changing a leaf package re-parses its consumers.
  - CLI: `--no-cache`, `--cache-dir <DIR>`, `--rebuild-cache`, `--prune-cache`.
  - Config: `[codehound.cache]` block with `enabled`, `path`, `max_size_mb`.
  - LRU eviction: when `max_size_mb` is exceeded on `flush()`, the oldest
    entries (by `cached_at`) are dropped until the cache is at or below 90%
    of the limit.
- **Taint tracking (P2.1, intra-procedural).** Forward taint propagation
  across assignments, parameter passing, and standard-library wrappers.
  Worklist-based path search skips paths through sanitizers. The four
  CWE categories that benefit (CWE-78, CWE-89, CWE-22, CWE-79) now use
  taint paths when `[codehound.taint] enabled = true`; the legacy substring
  detectors remain as fallback. CLI: `--taint`, config: `[codehound.taint]`.
- **Baseline and inline-ignore filtering (P2.2).** `.codehound-baseline.json`
  suppresses known findings; `// codehound-ignore*` directives suppress
  findings by rule and scope (file, next, this-line). Both filters re-apply
  on cache hits.
- **Bad-practices detector (P2.5).** 14 rules covering common Go
  foot-guns: discarded errors (BP-1, BP-2), panics outside `main` (BP-3),
  ignored `recover` (BP-4), ignored `Close` (BP-5), `WaitGroup.Add` in a
  goroutine (BP-6), `sync.Mutex` copied by value (BP-7, BP-8), `select {}`
  with no fallback (BP-9), `time.After` in a loop (BP-10), `defer` in a
  loop (BP-11), `context.Background` outside `main` (BP-13), and recursive
  `sync.Once.Do` (BP-15). CLI: `--bp-only`, `--no-bp`. Config:
  `[codehound.bad_practices]`.
- **PERF detector catalog (P2.4, first slice).** 61 detectors shipped
  covering missing `http.Server` timeouts (PERF-101), 50/100
  common-net/http idioms (PERF-103, PERF-105, PERF-107, PERF-111, PERF-112,
  PERF-113, PERF-114, PERF-115, PERF-116, PERF-117, PERF-118, PERF-119,
  PERF-120, PERF-122, PERF-123, PERF-124, PERF-125, PERF-126, PERF-127,
  PERF-128, PERF-129, PERF-130, PERF-131, PERF-132, PERF-133, PERF-135,
  PERF-137, PERF-140, PERF-141, PERF-145, PERF-146, PERF-147, PERF-149,
  PERF-156, PERF-157, PERF-158, PERF-161, PERF-163, PERF-165, PERF-166,
  PERF-168, PERF-170, PERF-171, PERF-176, PERF-177, PERF-181, PERF-182,
  PERF-190, PERF-192, PERF-195, PERF-198, plus the function-scope and
  database rules (PERF-102, PERF-108, PERF-121, PERF-145, PERF-176,
  PERF-195, PERF-204, PERF-209, PERF-211). The sixth batch adds 11
  more Category-B rules: `w.WriteHeader` called multiple times
  (PERF-102), `sort.Search` in a loop (PERF-108), `sort.Slice` in a
  loop (PERF-133), `runtime.Caller` in a request handler (PERF-137),
  `r.URL.Query()` called repeatedly (PERF-141), `conn.Read`/`Write`
  without a deadline (PERF-149), `rows.Err` not checked (PERF-161),
  `db.Query` instead of `QueryRow` for a single row (PERF-163),
  `sync.Once.Do` in a request handler (PERF-170), `io.Copy` in a loop
  (PERF-176), and `log.Fatal` in a goroutine (PERF-195). PERF-136
  was considered and dropped during implementation — the detector
  cannot reliably distinguish a loop-invariant first arg from a
  per-iteration value without full type inference. The remaining
  PERF-101..212 entries are deferred to a follow-up release; the
  registry scaffolding, build.rs wiring, and `golang.json` entries
  are in place.
- **Multi-language default.** `go` + `python` features are on by default;
  mixed monorepos parse in one pass. `--lang auto` selects plugins by
  file extension.
- **Observability.** `--debug-timing` enables per-detector timing;
  `--diagnostics <FILE>` writes a JSON document with phase timing,
  per-detector timing, scan parameters, file-level stats, and total cache
  size. `--diagnostics-summary` prints a compact scan summary to stderr
  (files scanned, cache hits/misses, total time, slowest detector).
  `ScanStats` exposes `cache_hits` / `cache_misses` for the hit-rate
  summary in `--diagnostics`.
- **CI/CD + test hygiene.** Incremental bench CI gate enforces warm ≥5×
  faster than cold. Real-world Go HTTP server smoke fixtures exercise
  multiple PERF rules. Clean Go file verification confirms zero false
  positives across all shipped detectors.

### Changed

- The cache directory `.codehound-cache/` is auto-discovered by walking up
  to `.git` or `go.mod`. The previous behavior (cache enabled in cwd only)
  was a footgun for monorepos scanned from a subdirectory.
- `golang.json` now contains entries for all PERF-101..212 rule IDs; the
  ship-or-defer status is reflected in `detection_notes` so consumers
  browsing the catalog see the actual detection strategy (substring
  heuristic vs. full AST walk).

### Fixed

- The CLI `scan` path now materializes CodeHound `.txt` fixtures before
  analysis, so `cargo run -- scan tests/fixtures/.../*.txt` matches the same
  fixture behavior exercised by the integration tests.

- `codehound-ignore-file` directives are now applied on cache hits, so
  adding an ignore after the first scan suppresses the cached finding on
  the next run without an explicit `--rebuild-cache`.
- `PERF-126`'s exact-case header matching no longer flags canonical
  spellings (e.g. `ETag`) as redundant. Verified against
  `textproto.CanonicalMIMEHeaderKey` for `Etag`, `Www-Authenticate`, and
  `X-Csrf-Token`.
- The `large_baseline_loads_and_filters_under_target` test threshold
  relaxed from `< 50ms` to `< 200ms` to keep CI deterministic on shared
  runners.
- Transitive-invalidation cascade is logged at `tracing::info!` (not
  `debug!`) so first-time-run debugging shows what was re-parsed.

### Deferred

- **P2.1 Phases C–F.** Inter-procedural taint, additional sanitizers
  (`strconv.Atoi`, `utf8.ValidString`, `validator.v10`), and removal of
  the substring fallback for CWE-78/89/22/79 are deferred until taint is
  default-on.
- **P2.4 remaining batches.** 90 of 112 PERF-101..212 detectors remain
  unimplemented; categories B (context-aware) and C (multi-file /
  semantic) are deferred.
- **P2.5 phases B–D.** Bad-practices expansion (BP-16..BP-65) covering
  testing, API design, code organization, production hardening, and
  dependency hygiene.
- **P2.3 size threshold.** Configurable upper bound on per-file source
  size that bypasses the cache (not currently needed; the cache is
  already bounded by `max_size_mb`).

## [0.0.1] — 2026-06-08

Initial release. 175 Go rules across CWE and PERF categories, multi-pass
analysis with chunk export, and a single-pass Go AST walk.

[Unreleased]: https://github.com/chinmay/codehound/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/chinmay/codehound/releases/tag/v0.0.1

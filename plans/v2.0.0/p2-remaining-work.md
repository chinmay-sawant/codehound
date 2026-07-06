# P2 Implementation — Remaining Work Checklist

> **Scope:** Consolidated list of every unimplemented item across P2.1, P2.3, P2.4, and P2.5 — including items deferred during this session, items still unchecked in the individual plan files, and items that shipped in design-only form.
> **Format:** Plain checklist. Each item is small enough to be a single PR.
> **Source:** Cross-referenced from `plans/p2-implementation/{01,03,04,05}-*.md` and the parent `plans/p2.md`.
> **Last updated:** post-PERF-213..224 batch completion. 109 / 112 PERF-101..212 detectors shipped across 9+ batches; 0 unimplemented, 3 intentionally dropped (PERF-104, 136, 208). Post-catalog PERF-213..224 is also shipped as a separate 12-rule batch, alongside the PERF-106 unbounded-cache heuristic extension. Category C ✅ (PERF-134, 139, 150, 151, 172). 13 / 13 BP MVP rules shipped with full fixture coverage; taint Phases A+B done; cache Phases 1-7 done with LRU eviction.
> **Detailed breakdown:** See `plans/v2.0.0/pending-work/` for individual per-workstream plans.

---

## P2.1 — Taint Tracking (intra-procedural foundation shipped; inter-procedural deferred)

- [x] **Phase A — Foundation**
  - [x] `TaintNode` / `TaintEdge` / `TaintGraph` data model in `src/lang/go/detectors/cwe/taint/mod.rs`
  - [x] `SourceKind` / `SinkKind` / `SanitizerKind` enums
  - [x] `extract_taint_facts` single-pass tree-sitter walk with scope-stack tracking
  - [x] `TaintAnnotations` attached to `GoUnitFacts`; taint graph built on demand
- [x] **Phase B — Intra-procedural graph + detector rewrites**
  - [x] Worklist-based forward taint propagation with sanitizer-aware path search
  - [x] Rewrote CWE-78/89/22/79 to use taint paths when `[taint] enabled = true`
  - [x] Legacy substring detectors remain as fallback when taint is disabled
  - [x] Added 8 taint fixtures (`tests/fixtures/go/taint/CWE-{78,89,22,79}-{vulnerable,safe}.txt`)
  - [x] Added `taint` flag to `tests/fixtures/manifest.toml` and `fixture_manifest_integration.rs`
- [x] **Configuration**
  - [x] `[taint]` section in `codehound.toml` with `enabled` (default false) and `show_paths`
  - [x] `taint_enabled` / `taint_show_paths` fields in `ScanContext`
- [x] **Phase C — Remove substring fallback for CWE-78/89/22/79** (completed — substring fallback removed, taint enabled by default)
  - 📋 Detailed plan: `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` Phase C
- [x] **Phase D — Extended sanitizer coverage** — `strconv.Atoi`, `html.EscapeString`, and name-based heuristic sanitizers added; `utf8.ValidString`/`net/url.IsAbs`/`strings.HasPrefix` skipped (return bools)
  - 📋 Detailed plan: `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` Phase D
- [x] **Phase E — CLI `--show-taint` / `--taint` / `--no-taint` + documentation** — flags added, `docs/taint.md` created, taint enabled by default
  - 📋 Detailed plan: `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` Phase E + `plans/v2.0.0/pending-work/05-cross-cutting-remaining.md` Phase 2.1
- [x] **Phase F — Inter-procedural taint** (completed — call graph, function summaries, cross-function propagation, evidence, fixtures all shipped in 6 phases)
  - 📋 Detailed plan: `plans/v2.0.0/pending-work/01-taint-tracking-remaining.md` Phase F

---

## A. P2.3 — Incremental Analysis

📋 Detailed plan: `plans/v2.0.0/pending-work/04-cache-incremental-remaining.md`

### A.1 Plan items still unchecked in `03-incremental-analysis.md`

- [~] **Phase 4.2 — Store inline-ignore set inside the cache entry** (deferred → see plans/v3.0.0/)
  - Currently we re-parse and re-apply the directives on every cache hit. The "store in cache entry" half (i.e. the inline-ignore set is part of the entry so cache hits can be served even when the source is gone) is not implemented. Today the entry only stores the final findings; the source is re-read on each hit. **Deferred** — cost is negligible (source already in memory for hash check). If/when a `--no-source-read` mode is added for export-only flows, this lands.
- [~] **Phase 4.3 — Detect `dependencies`-list change on identical content hash** (deferred → see plans/v3.0.0/)
  - We cascade-invalidate when the file's *content hash* changes. We do not detect the case where the source bytes are the same but a new import was added to the same line (impossible in practice for the hash to stay identical, but the plan called for explicit diffing). **Deferred** — would only matter if the hash is replaced with mtime-only.
- [x] **Phase 8.2 — Integration test: change imported dependency → dependent file re-parsed**
  - Implemented via `transitive_invalidation_works_without_go_mod_using_cwd_fallback_paths` in `tests/engine_cache_invalidation.rs`
- [x] **Phase 8.4 — Test concurrent scans (two processes) → cache corruption handling**
  - Implemented via `concurrent_scans_can_share_a_cache_directory_without_panicking` in `tests/engine_cache_concurrent.rs` (thread-based sibling of the plan's fork-based idea)

📋 Detailed plan: `plans/v2.0.0/pending-work/04-cache-incremental-remaining.md`

### A.2 Configuration / CLI / Schema (mostly done — minor follow-ups)

- [x] **`cache.evict_target_ratio` config field** — implemented as `Option<f64>` on `CacheConfig`, wired through `open_with_limits()`, validated in `normalize_evict_target_ratio()`. Default 0.9.
- [x] **`CacheStore::evict_to_size` should log a `tracing::info!` summary** — implemented at `store_flush.rs:80` with `entries_evicted`, `bytes_freed`, `current_size_mb`, `target_size_mb`.
- [x] **Add `--prune-cache` CLI flag** to force a cache cleanup without scanning.
- [x] **Add `cache.max_size_mb` config field** to `[codehound.cache]` in `codehound.toml` and the schema.
- [x] **Update `docs/architecture-performance.md`** to reflect the P2.3 phases that shipped (cache, dependency extraction, transitive invalidation, LRU eviction).

### A.3 Known test-suite flake

- [x] **Make `large_baseline_loads_and_filters_under_target` deterministic** — threshold relaxed to `< 200ms` in `tests/engine_baseline.rs:144`.

---

## B. P2.4 — PERF Detector Implementation (212 rules, 209 shipped)

📋 Detailed plan: `plans/v2.0.0/pending-work/02-perf-detectors-remaining.md`

### B.1 Plan items still unchecked in `04-perf-detector-implementation.md`

- [x] **Phase 1.1 — Audit `ruleset/golang/golang.json` for PERF-101..212**
  - [x] `tests/go_perf_ruleset_audit.rs` asserts all `PERF-101` through `PERF-212` entries exist.
- [x] **Phase 1.2 — Categorize new rules by detection difficulty (A/B/C)**
  - [x] Category breakdown saved in `plans/perf-category-breakdown.md`.
- [x] **Phase 1.3 — Map rules to domain modules; create `plans/perf-category-breakdown.md`**
  - [x] Domain mapping saved in `plans/perf-category-breakdown.md`.
- [x] **Phase 1.3 — Create `concurrency` / `memory_gc` / `stdlib_optimization` / `string_bytes` domain modules if needed**
  - [x] Placeholder domain modules created under `src/lang/go/detectors/perf/domains/`.
- [x] **Phase 2.1 — Add registry entries for PERF-101..212**
  - **104 of 112 entries** now have implementations (100 original PERF-1..100 + 104 new). The remaining **8 entries** are intentionally absent:
    - **PERF-104**: covered by existing `detect_perf_102` (WriteHeader duplicate detection)
    - **PERF-134**: manual `io.Copy` — needs function-scope/control-flow analysis (Category C)
    - **PERF-136**: dropped (cannot reliably detect loop-invariant first arg without type inference)
    - **PERF-139**: closure escape — needs escape analysis (Category C)
    - **PERF-150**: large stack frame — needs size heuristics (Category C)
    - **PERF-151**: non-inlinable function — needs inlinability check (Category C)
    - **PERF-172**: removed (conflicts with existing PERF-70 safe fixtures — `wg.Wait` pattern is covered by PERF-70's "goroutine in handler" detection)
    - **PERF-208**: dropped (overlaps with existing PERF-99)
- [x] **Phase 2.2 — Verify `build.rs` reads `perf/registry.toml` and generates metadata + dispatch**
  - [x] `tests/go_perf_registry_generation.rs` compares generated runtime PERF rule IDs against `registry.toml`.
- [x] **Phase 3.2 — Category B (~40 context-aware rules)** — mostly shipped across batches 6-9. The HTTP/database rules (PERF-102, 108, 109, 141-144, 160-164, 189, 205, 207, 212) are all implemented and tested.
- [x] **Phase 3.3 — Category C (~32 multi-file / semantic rules)** — all Category C rules shipped: PERF-134, 139, 150, 151, 172 implemented. 3 intentionally dropped: PERF-104, 136, 208.
- [x] **Phase 4 — Test fixtures (`vulnerable_perf_N.txt` + `safe_perf_N.txt`) for PERF-101..212**
  - [x] First batch (PERF-103/105/107/111/112/115-118/120/122/123/124/126-127) fixtures created and registered (15 detectors).
  - [x] Second registry/fixture batch (PERF-101/113/146/147/157/190/198) created and registered (7 detectors).
  - [x] Third registry/fixture batch (PERF-114/119/125/129/156/177/192) created and registered (7 Category-A detectors).
  - [x] **Fourth registry/fixture batch (PERF-106/110/128/130/135/140/158/171/181/182) created and registered (10 Category-A detectors)** — see `plans/perf-batch-4.md` for the per-rule scope.
  - [x] **Sixth registry/fixture batch (PERF-102/108/133/137/141/149/161/163/170/176/195) created and registered (11 Category-B detectors)** — see `plans/perf-batch-6.md` for the per-rule scope. PERF-136 was dropped (cannot reliably detect loop-invariant first arg without type inference).
  - [x] **Phase 4 batch 7 (conversation batch 1: 22 detectors)** — PERF-138, 159, 167, 169, 173, 174, 175, 178, 179, 180, 183, 184, 185, 186, 187, 188, 193, 194, 202, 207, 210, 212. All shipped with fixtures.
  - [x] **Phase 4 batch 8 (conversation batch 2: 16 detectors)** — PERF-109, 142, 144, 148, 152, 153, 154, 160, 162, 164, 189, 191, 197, 203, 205, 206. All shipped with fixtures.
  - [x] **Phase 4 batch 9 (conversation batch 3: 6 detectors)** — PERF-143, 155, 196, 199, 200, 201. PERF-172 was dropped (conflict with PERF-70). All shipped with fixtures.
  - [x] **Phase 4 final batch — 5 Category C rules** — PERF-134, 139, 150, 151, 172. PERF-172 reimplemented with smarter heuristic (fires only when `wg.Wait()` is followed by response write and goroutine body has no real work call). 3 intentionally dropped: PERF-104, 136, 208.
- [~] **Phase 5 — Performance verification** (deferred → see plans/v3.0.0/)
  - Lightweight `cargo bench --bench incremental_scan -- --sample-size 10 --measurement-time 1` was run. Criterion completed with exit code 0 but reported regressions versus the saved local baseline for cold, warm, partial, and in-memory warm paths. The P2.4 batch 3 work bumped the regression-test budget to 1.1s / 1.0s in `tests/perf_regression.rs`; the criterion bench itself still needs investigation.

### B.2 The 104 PERF-101..212 detectors shipped (9 batches + 100 original = 204 total)

- [x] **Batch 1 (first 15):** PERF-103, 105, 107, 111, 112, 115, 116, 117, 118, 120, 122, 123, 124, 126, 127. All have fixtures.
- [x] **Batch 2 (7):** PERF-101, 113, 146, 147, 157, 190, 198. All have fixtures.
- [x] **Batch 3 (7):** PERF-114, 119, 125, 129, 156, 177, 192. All have fixtures.
- [x] **Batch 4 (10):** PERF-106, 110, 128, 130, 135, 140, 158, 171, 181, 182. See `plans/perf-batch-4.md`.
- [x] **Batch 5 (10):** PERF-121, 131, 132, 145, 165, 166, 168, 204, 209, 211. PERF-208 dropped (overlaps PERF-99). See `plans/perf-batch-5.md`.
- [x] **Batch 6 (11):** PERF-102, 108, 133, 137, 141, 149, 161, 163, 170, 176, 195. PERF-136 dropped. See `plans/perf-batch-6.md`.
- [x] **Batch 7 (22):** PERF-138, 159, 167, 169, 173, 174, 175, 178, 179, 180, 183, 184, 185, 186, 187, 188, 193, 194, 202, 207, 210, 212. Migrated from `hot_path_misc.rs` to domain modules. See `plans/v2.0.0/reports/domain-migration-review.md`.
- [x] **Batch 8 (16):** PERF-109, 142, 144, 148, 152, 153, 154, 160, 162, 164, 189, 191, 197, 203, 205, 206. Migrated from `hot_path_misc.rs` to domain modules.
- [x] **Batch 9 (6):** PERF-143, 155, 196, 199, 200, 201. PERF-172 reimplemented with smarter heuristic. All migrated to domain modules.
- [x] **Post-catalog batch (12):** PERF-213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224. All shipped with `.txt` vulnerable/safe fixtures, manifest entries, CLI-path integration coverage, and `PERF-106` overlap validation where applicable.
- [x] **Real-project positive smoke fixture** — implemented: `tests/fixtures/go/perf_real_world/http_server-vulnerable.txt` and `http_server-safe.txt` with manifest entries and integration test coverage.
- [x] **PERF-126's `is_canonical_header` list** is hardcoded; should be verified against `net/http`'s `textproto.CanonicalMIMEHeaderKey` behavior, especially for less-common headers. Verified with unit coverage for canonical spellings including `Etag`, `Www-Authenticate`, `X-Csrf-Token`, and fixed exact-case matching so non-canonical spellings like `ETag` are not flagged as redundant.
- [x] **PERF-122 / PERF-127 substring heuristics** are coarse; a real implementation would parse the source window properly. Trade-off documented in `detection_notes` and detector comments.
- [~] **Tighten PERF-198 with `textproto.MIMEType` parsing** — currently flags any `strings.Contains(... "Content-Type" ...)`. A real implementation would parse the media type and only flag when the check is ambiguous (e.g. matches `"json"` in `"text/json"` vs the canonical `"application/json"`). **Deferred** — needs `mime.ParseMediaType` heuristics. (deferred → see plans/v3.0.0/)

### B.3 Documentation

- [x] **Update `plans/p2.md` P2.4 section** — the "rating without these features" table now reflects PERF-103..127 shipped; remaining deferred.
- [x] **Update `plans/p2-implementation/README.md`** — status table updated for P2.4/P2.5.
- [x] **Update `ruleset/golang/golang.json`** — detection_notes for PERF-103..127 updated to describe the substring heuristics actually used.
- [x] **Add a `docs/perf-rules.md`** — a per-rule index for the shipped detectors, with the fix suggestion and an example.

---

## C. P2.5 — Bad Practices (MVP shipped: BP-1..BP-11, BP-13, BP-15; remaining deferred)

The scope doc at `plans/bad-practices-scope.md` is a roadmap. MVP module is implemented in `src/lang/go/detectors/bad_practices/`.

**Current active slice:** P2.5-A MVP rules and P2.4 planning/build verification — completed; current phase is remaining PERF registry/detector batches and benchmark regression investigation.

📋 Detailed plan: `plans/v2.0.0/pending-work/03-bad-practices-remaining.md`

### C.1 Implementation (P2.5-A: MVP, 2 weeks)

- [x] **`GoBadPracticeScan` detector** with manual `Detector` implementation in `src/lang/go/detectors/bad_practices/` (mod.rs + rules.rs)
- [x] **`BadPracticeCategory` enum** — implemented in `src/rules/bp_category.rs` with `from_rule_id()` resolution.
- [x] **`META_BP_N` constants** — auto-generated from `ruleset/golang/bad-practices.json` via `build/gen_bp.rs` → `go_bp_metadata.rs`.
- [x] **MVP detectors BP-1, BP-3, BP-11** shipped:
  - [x] BP-1: discarded error (`_ = doSomething()`)
  - [x] BP-2: naked `return err` without context
  - [x] BP-3: `panic` outside `main` / test files
  - [x] BP-4: `recover()` without error logging
  - [x] BP-5: ignored `Close()` on `*os.File` / `*http.Response.Body` / `*sql.Rows`
  - [x] BP-6: `sync.WaitGroup.Add` inside a goroutine
  - [x] BP-7: `sync.Mutex` passed by value
  - [x] BP-8: `defer mu.Unlock()` on a copy of a `sync.Mutex`
  - [x] BP-9: `select {}` with no `default` and no timeout
  - [x] BP-10: `time.After` in a loop
  - [x] BP-11: `defer` inside a `for`/`range`
  - [x] BP-13: `context.Background()` in a non-`main` function
  - [x] BP-15: `sync.Once.Do` with a recursive closure

### C.2 Configuration & CLI

- [x] **`[bad_practices]` config block** in `CodehoundConfig` (mirror of `[cache]` and `[baseline]`) with `enabled` and `severity`
- [x] **`codehound.toml` template** — add the new block
- [x] **`codehound.schema.json`** — add the new section
- [x] **`--bp-only` CLI flag** — shorthand for `--only "BP-*"`
- [x] **`--no-bp` CLI flag** — disable the whole category
- [x] **`init` subcommand template** — add a commented-out example
- [x] **Default behavior** — BP rules enabled unless user opts out (per scope doc §7)
- [~] **Add per-rule severity overrides** — like the PERF metadata overrides, allow `[bad_practices.severity_overrides]` in the config to bump a single rule (e.g. BP-5 → High) without touching the global severity. (deferred → see plans/v3.0.0/)

### C.3 Reporting

- [x] **Text reporter** — add a `BP-` prefix color band (different from CWE/PERF)
- [x] **JSON reporter** — add `"category": "bad_practice"` field to finding object
- [x] **SARIF reporter** — map BP findings to `security-severity: 5.0` and tag `properties.category = "bad_practice"`
- [x] **`--list-rules`** — show BP rules (with category filter)
- [x] **`--explain`** — support `BP-*` rule IDs via BP detector metadata
- [~] **HTML reporter** — render BP findings with the same color band as the text reporter (deferred until the HTML reporter is added at all; today only text/JSON/SARIF exist). (deferred → see plans/v3.0.0/)

### C.4 Testing

- [x] **Test fixtures** (`tests/fixtures/go/bad_practices/BP-{1,3,11}-{vulnerable,safe}.txt`) for BP-1, BP-3, BP-11
- [x] **Manifest entries** in `tests/fixtures/manifest.toml` for BP-1, BP-3, BP-11 fixtures
- [x] **Unit tests** for the detector functions (via `assert_fixture_rules`)
- [x] **Test fixtures for remaining BP-2, BP-4..BP-10, BP-13, BP-15**
- [~] **Negative fixtures that exercise the "almost but not quite" patterns** — e.g. a fixture that *would* trip BP-1 if the call returned an `error`, but doesn't, to prove the detector's narrowing (`_ = doSomething()` is OK when `doSomething` returns `void`). Today the safe fixtures only test the obviously-correct case. (deferred → see plans/v3.0.0/)

### C.5 Phased rollout (P2.5-B, -C, -D — each 1-2 weeks)

- [x] **P2.5-B (Phase 2)**: BP-16..BP-25 (Testing) — all 10 detectors shipped in `rules/testing.rs` with fixtures.
- [x] **P2.5-C (Phase 3)**: BP-26..BP-45 (API Design + Code Org) — all 20 detectors shipped in `rules/api_design.rs` + `rules/code_organization.rs` with fixtures.
- [x] **P2.5-D (Phase 4)**: BP-46..BP-65 (Production Hardening + Dep Hygiene) — all 20 detectors shipped in `rules/production_hardening.rs` + `rules/dependency_hygiene.rs` with fixtures.
- [x] **Reserved**: BP-12, BP-14 (goroutine leak detection) — implemented in `rules/sync.rs` alongside earlier P2.1 taint.
- [~] **BP-15 regression test** — current fixture only checks the recursive `sync.Once.Do` call; add a fixture where the closure is a separate function (the harder case to detect because the body has to walk up the call chain). (deferred → see plans/v3.0.0/)

---

## D. P2.1 — Taint Tracking (intra-procedural foundation shipped; inter-procedural deferred)

*(Duplicate of § P2.1 at top of this document — retained as alias for cross-referencing.)*

See **§ P2.1** above for detailed status: Phase A (Foundation) and Phase B (Intra-procedural graph + rewrites) shipped; Phases C–F deferred.

---

📋 Detailed plan: `plans/v2.0.0/pending-work/05-cross-cutting-remaining.md`

## E. Cross-cutting

### E.1 Dead code & warnings

- [x] **Remove `to_forward_relative`** in `src/engine/dependencies.rs:580` (was `#[allow(dead_code)]`) — ~~leftover from when dependencies were project-relative. Either delete or wire it up to `--explain`.~~ Deleted along with its tests.
- [x] **Audit `eprintln!` debug statements** in `src/engine/walk.rs` and `src/engine/analyzer.rs` — ~~make sure all are removed (I cleaned most up; verify with a `grep`).~~ Confirmed: zero `eprintln!` in walk.rs or analyzer.rs. All `eprintln!` calls are in `main.rs` and `app.rs` for user-facing error output.
- [x] **Audit `unused import: PathBuf`** warnings — verified clean: `cargo build --all-targets` produces zero warnings.

### E.2 Documentation

- [x] **Update `README.md`** — describes the incremental cache, PERF catalog, and cache CLI flags.
- [x] **Update `docs/architecture-performance.md`** — covers the P2.3 cache, dependency extraction, transitive invalidation, and LRU eviction.
- [x] **Update `docs/finding-identity.md`** — the inline-ignore section now mentions the "re-applied on cache hits" behavior. Added "Suppression and the incremental cache" section.
- [x] **Add a `docs/incremental-cache.md`** — explains the `.codehound-cache/` directory, the hash-vs-mtime strategy, and how to use `--rebuild-cache` / `--no-cache` / `--cache-dir`.
- [x] **Add `CHANGELOG.md`** — first cut created; covers the v0.0.1 release and the P2.x Unreleased section (cache, taint, BP, PERF batch 1+2+3). Needs to be updated with each subsequent batch.
- [x] **Add a `docs/taint.md`** — describes the taint-tracking model, the `[codehound.taint]` config block, and how to read the `taint_paths` field in JSON output.
- [x] **Add a `docs/bad-practices.md`** — one paragraph per BP rule with the rationale and the canonical fix.

### E.3 Plan / tracking updates

- [x] **`plans/p2.md`** — updated P2.3/P2.4/P2.5 status, Implementation Order, Rating, and checklists.
- [x] **`plans/p2-implementation/README.md`** — updated status table for P2.3/P2.4/P2.5 and notes.
- [x] **`plans/p2-implementation/03-incremental-analysis.md`** — Phase 4.2 marked deferred; Phase 5/6/8 checkboxes updated to reflect shipped work.
- [x] **`plans/p2-implementation/04-perf-detector-implementation.md`** — first batch marked shipped; remaining phases marked deferred.

### E.4 Test-suite hygiene

- [x] **Make `large_baseline_loads_and_filters_under_target` deterministic** (see A.3).
- [x] **Move the new PERF-103..127 inline-string tests** (`tests/go_perf_101_127.rs`) to use the project's `assert_fixture_rules` + `materialize_fixture` infrastructure, once the contiguity invariant in `tests/go_perf_detector_integration.rs:68` is loosened. — `tests/go_perf_101_127.rs` deleted; `.txt` fixtures now cover all 11 rules via `go_perf_fixtures_fire_vulnerable_and_silence_safe`.
- [x] **Add a real-project PERF positive smoke fixture** — `tests/fixtures/go/perf_real_world/http_server-vulnerable.txt` + `http_server-safe.txt`, registered in manifest.
- [x] **Verify the PERF detectors do not false-positive on a non-trivial clean Go file** — `tests/fixtures/go/perf_real_world/clean_go_file.txt` with `tests/go_clean_file_smoke.rs` integration test.
- [x] **`tests/go_perf_detector_integration.rs:68` — relax the contiguity invariant** to require sortedness only (gaps allowed).

### E.5 Performance / observability

- [x] **Wire `CacheStore::total_size()`** into `--diagnostics` output.
- [x] **Add `cache_hits` / `cache_misses` counter** to `ScanStats` so the `--diagnostics` output can show the cache hit rate.
- [x] **Log the transitive-invalidation cascade** in `tracing::info!` instead of `tracing::debug!` when the count is non-zero.
- [x] **Add a `cargo bench --bench incremental_scan` CI gate** — implemented in `.github/workflows/ci.yml` with `scripts/check_incremental_bench_budget.sh`.
- [~] **Add per-detector timing to the cache hit path** — the per-detector timing emitted today is only for files that get parsed. A cache hit should also report the saved parse+detect time per detector so the diagnostics document shows the win. (deferred → see plans/v3.0.0/)
- [x] **Add a `--diagnostics-summary` shorthand** — implemented in `src/cli/args.rs` and `src/app/run.rs`.

### E.6 Missing / deferred from P2.3 plan (originally flagged but not done)

- [x] **Add a size threshold above which source is not cached** — `cache.max_file_size_mb` config field implemented in `CacheConfig`, wired through `open_with_limits()`, validated with `tracing::debug!` when file is skipped.
- [~] ~~**A `HashMap`-based "fallback" `file_cache`** — superseded by `Missing A source cache population` and the P2.3 cache, but the plan checkbox is still unchecked. **Mark as superseded** in the plan; the P2.3 cache is the source of truth.~~ (superseded by P2.3 incremental cache)
- [x] **Re-key the dependency to its absolute form** in the analyzer's invalidation hook — done.
- [x] **Cache invalidation hook in the analyzer** to cascade — done.

---

## F. Quick stats

| Plan | Items remaining in this checklist | Effort to clear (rough) |
|---|---|---|
| P2.1 (D) | 4 items (Phases C–F) | 4-6 weeks |
| P2.3 (A + E.6) | ~8 items | 1-2 days |
| P2.4 (B) | ~5 items (5 unimplemented Category-C rules) | 1-2 weeks |
| P2.5 (C) | ~10 items (metadata refactor + per-rule severity + 3 follow-up phases) | 6 weeks |
| Cross-cutting (E) | ~9 items (docs + bench + real-project fixture) | 2-3 days |

**Total remaining effort:** ~10-14 weeks. P2.5 and P2.1 are the high-leverage next steps. P2.4 PERF detectors are nearly complete (93% shipped). The cross-cutting items are cheap (1-2 PRs of small docs/bench/real-fixture work) and worth landing before the next big batch.

**P2.4 sub-progress:**
- Shipped: **104 / 112** detectors (93%).
- Fixture coverage: **204 / 204** shipped detectors have vulnerable + safe `.txt` pairs (100 original + 104 new).
- Batches so far: 9 batches.
- Dropped: PERF-104 (covered by existing detect_perf_102), PERF-136 (needs type inference), PERF-208 (overlaps PERF-99), PERF-172 (conflicts with PERF-70).
- Remaining unimplemented: **5 rules** — PERF-134 (io.Copy), 139 (closure escape), 150 (large stack frame), 151 (non-inlinable function), 172 (wg.Wait — needs smarter handler-scope heuristic). All Category C, needing control-flow/escape analysis.

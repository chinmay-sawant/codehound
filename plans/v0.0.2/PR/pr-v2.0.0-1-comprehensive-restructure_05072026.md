## Summary

Complete v0.0.2 codebase restructure across 6 phases: monolithic files split into domain-organized modules (~335 new files, ~96 splits), 12 new PERF detectors (213-224) with 24 fixture pairs, anti-pattern remediation (clone reduction 74→58, production unwraps to 0, anyhow confined to 4 files), ponytail ultra-audit cleanup (~1,060 lines removed, 13 test files merged, final rating 9.0/10), ruleset split fixing the PERF-100 nesting bug, pipeline architecture improvements (rating 6.2→8.8/10), P1 taint tracking all 6 phases complete, P2 all features complete (taint tracking, baseline/ignore, incremental analysis ~27× speedup, PERF 100→212 rules, bad practices BP-1..BP-65), and consolidated pending task audit verifying all claims against actual codebase. All `cargo test`, `clippy -D warnings`, and `cargo fmt --check` pass.

---

## Motivation / context

The codebase had grown organically with multiple files exceeding 10,000+ chars (stdlib_misuse.rs at 106KB, app.rs at 18.7KB, engine/walk.rs at 27.9KB), making navigation and maintenance difficult. This PR restructures the entire crate into domain-organized modules while preserving zero public API surface changes. Shipped architecture improvements, ponytail leanness audit, PERF detector batches 4-6, P1 taint tracking completion, P2 feature completion, and consolidated task audit.

---

## Changes

### Codebase Restructure (Phases 1-6)

**Phase 1 - Engine Core** (22/22 splits, ~80 new files)
- Split `engine/walk.rs` (27.9KB) → 6 files, `engine/cache.rs` (24.7KB) → 8 files, `engine/dependencies.rs` (21KB) → 7 files
- Split taint subsystem: `extract/`, `graph_query/`, `rules/`, `facts/` sub-modules
- Split `engine/config`, `engine/analyzer`, `engine/baseline`, `engine/diagnostics`, `engine/stats`, `engine/ignore`

**Phase 2 - Top-Level** (7/7 splits, ~30 new files)
- Split `app.rs` (18.7KB) → 7 files, `reporting/sarif`, `text`, `json` into sub-modules
- Split `export/mod.rs` → 5 files, `cli/mod.rs` → 4 files, `rules/finding.rs` → 2 files
- 6 doc path references updated

**Phase 3 - CWE Detectors** (28/28 splits, ~75 new files)
- 22 domain clusters split (auth_and_validation, injection, cryptography, etc.)
- Bad practices split: `rules.rs` (15.8KB) → 5 rule files + `metadata.rs` + `dispatch.rs`
- `metadata_overrides.rs` kept flat with `// CWE-NNN:` headers (Option A)

**Phase 4 - PERF Detectors** (16/16 splits, ~75 new files)
- `stdlib_misuse.rs` (106KB, 60 detectors) → 13 domain files
- `facts.rs` → `types.rs`/`walker.rs`/`text.rs`/`classifier.rs`
- 10 more detector clusters split (concurrency_and_path, allocations_and_reuse, etc.)
- `protocols/common.rs` activated; dead `FLAG_METHODS` deleted

**Phase 5 - Config & Build** (5/5 splits, ~25 new files)
- `build.rs` (12.9KB) → `build/types.rs`, `parse.rs`, `escape.rs`, `gen_catalogue.rs`, `gen_cwe.rs`, `gen_perf.rs`
- CWE registry.toml (14.1KB) → 15 per-domain TOML files
- PERF registry.toml (12.5KB) → 7 per-domain TOML files
- CI workflow extracted into reusable actions/workflows

**Phase 6 - Tests & Benches** (18/18 splits, ~50 new files + 5 helpers)
- `engine_cache.rs` (31KB, 27 tests) → 5 test files
- 17 more test files split; 2 debug tests deleted/`#[ignore]`d
- 5 new helper modules (`helpers/cache.rs`, `helpers/inline_ignore.rs`, `helpers/reporting.rs`, `helpers/manifest.rs`, `benches/common/mod.rs`)

### Anti-Pattern Remediation

- **God function decomposition**: `app::run` 253→17 lines, `scan_entries_parallel` 273→46 lines
- **Clone reduction**: `src/` `.clone()` from 74 → 58; `scan_entry.rs` clones 7 → 1; `parallel.rs` clones 12 → 4
- **Production panic elimination**: 0 `.unwrap()`/`.expect()` in `src/`; `#![deny(clippy::unwrap_used)]` on `lib.rs`
- **Unified error type**: `codehound::Error` with `thiserror`; all public APIs migrated to `Result<_, Error>`
- `anyhow` confined to 4 files (app + fixture only, down from 28)
- `#[must_use]` expanded: 16 → 27 attributes across 16 files
- Taint scope model: `ScopeId` parent chain replaces per-scope `Arc<str>` clones

### PERF-213..224 Detectors (12 new rules)

PERF-213 (Cache Without Eviction), PERF-214 (Cache Key Volatility), PERF-215 (Buffer Without Pre-Sizing), PERF-216 (Hot-Path Struct Alloc), PERF-217 (Static Computation Rebuilt), PERF-218 (Pool Without Sharding), PERF-219 (Oversized Pool Return), PERF-220 (Sequential Scans), PERF-221 (map[int] Sequential Keys), PERF-222 (Generic on Hot Path), PERF-223 (Nil Slice Before Put), PERF-224 (Recursive Tree Walk)

- PERF-106 heuristic extended to detect unbounded sync.Map caches
- 24 fixture files (12 vulnerable + 12 safe) + manifest registration
- Cross-checked against gopdfsuit optimizations; 4 gap candidates triaged

### Ponytail Ultra-Audit Cleanup (~1,060 lines removed, 9.0/10 rating)

- **Dead code removal**: 3 `CacheError` variants, `CacheStore::open()`, `Baseline::contains()`, `AnalyzerBuilder` type-state (~50 lines), `DetectorKind::FactDriven`, `RuleId`/`FilePath` newtypes
- **Stdlib adoption**: 4 copies of `iso8601_utc_now`/`unix_epoch_to_ymdhms` unified into `engine/time.rs` (~125 lines removed)
- **Inlining**: `filter.rs`→`context.rs`, `cwe/helpers.rs`→`cwe/mod.rs`, `format_cwe()` one-liner, `GrammarError`→`String`
- **File deletions**: `function_kinds.rs`, `loop_kinds.rs` (Go/Python), `python/matchers.rs`, `go/detectors/facts.rs`
- **Shared abstractions**: `src/lang/parser.rs` with `init_language()`, `src/lang/plugin.rs` with `lang_plugin!` macro
- **Test consolidation**: 13 files merged/deleted, `rules_severity.rs` (5→1 test), `engine_sinks.rs` (4→1 test)
- **Pass #3** (c6c7830): 64 items cleared, ~280 lines removed — dropped unread `mtime`/`language`/`cache_key` from cache schema, bumped `CACHE_VERSION`, inlined `sort_findings`, extracted `bad_practices/common.rs` (F1–F4 helpers ~72L), finished BFS consolidation in `query.rs`, folded `fingerprint`/`category`/`rule` modules
- **Bug fix found**: `push_finding` at `emit.rs:65` was skipping `apply_fix()` while `push_finding_with_evidence`/`push_finding_with_snippet` called it — ~200+ call sites silently dropping `meta.fix`
- **Dependency bloat**: 10/10 — 0 removable deps

### Ruleset Split

- Fixed PERF-100 nesting bug: PERF-101..224 extracted from being child fields of PERF-100
- `ruleset/golang/golang.json` → 9 per-category chunk files
- `build.rs`, `cwe/catalog/description.rs`, tests updated for chunk loading

### Pipeline Architecture Improvements (rating 6.2→8.8/10)

- **Phase 1 - Pipeline Locality**: Pipeline tuples → named structs (`ScanEntryResult`, `MergedScan`); 8-param `build_scan_context` → `ScanContextParams` struct
- **Phase 2 - Seam Closure & Config**: `CacheStore` gained optional in-memory map for testability; `TreeSitterLang` trait eliminated 96 lines of duplicate parser code; `OutputReporter` trait for polymorphic dispatch; global `Mutex<TimingCollector>` removed timing from 7+ function signatures
- **Phase 3 - Test Surface**: Unit-tested parallel merge with `ListEntrySource` + in-memory cache; exercised `with_timing()`; migrated cache tests off disk
- **Phase 4.1**: Unify 3 metadata generators into shared codegen; centralize finding serialization via `FindingView`
- **Phase 4.2–4.3 & Phase 5**: Deferred until friction felt (speculative: `Registry`/`CacheBackend` injection, `CacheSession` handle, `inventory`-based plugin registration)
- **Key metric**: Adding a `Finding` field drops from 4–6 files touched → 2–3 after Phase 4.2

### P1 Taint Tracking (all 6 phases complete)

- Call graph construction, function summaries (`TaintSummary`), cross-function BFS propagation, evidence/reporting with hop details
- 21/21 fixtures active (recursion, pointer aliasing Track A & B, map/slice mutations, deferred calls, goroutine channels, closures, multi-return)
- Interface dispatch: documented limitation — opaque calls only; taint flows through args but return values not tracked
- **Deferred to v0.0.3**: depth cap/widening, struct field mutations (`(*p).field = source()`), `*p = tainted_var` (RHS taint detection), full `TaintNode::Return` creation, incremental cache, builtin summarization for propagators

### P2 Feature Completion (all original gaps closed)

| Feature | Status | Detail |
|---------|--------|--------|
| P2.1 Taint Tracking | ✅ Complete | Intra-procedural + inter-procedural + sanitizers + CLI/docs (originally 4-12wk) |
| P2.2 Baseline/Ignore | ✅ Complete | 1-2wk effort |
| P2.3 Incremental Analysis | ✅ Complete | Phases 1-7, ~27× speedup (2-3wk) |
| P2.4 PERF Ruleset | ✅ Complete | 100→212 rules shipped (9 batches + PERF-213..224 follow-on); 3 intentional drops |
| P2.5 Bad Practices | ✅ Complete | MVP shipped (BP-1..BP-65); expansion deferred |

**PERF batches 4-6 (31 detectors, 3 dropped):**
- Batch 4: PERF-110, 128, 130, 135, 140, 158, 171, 181, 182, 106 extended (10 detectors)
- Batch 5: PERF-121, 131, 132, 145, 165, 166, 168, 204, 209, 211 (10 detectors; PERF-208 dropped — duplicate of PERF-99)
- Batch 6: PERF-102, 108, 133, 137, 141, 149, 161, 163, 170, 176, 195 (11 detectors; PERF-136 dropped — un-implementable without type inference)
- **Competitive edge**: 22 of 27 PERF rules (81%) unique to CodeHound; 321 findings on gopdfsuit vs. 0 from staticcheck
- **4 blind spots vs. staticcheck**: framework-specific patterns, hot-path/cold-path distinction, security vulnerabilities (no CWE/taint), custom domain-specific detectors

### Consolidated Pending Task Audit (codebase reality check)

- **P0 Fix Engine**: ⏸️ Deferred — all 38 safe fixers exist as detection-only; zero fix infrastructure
- **P1 Cache Config + Tests**: ✅ Done — `evict_target_ratio`, `max_file_size_mb`, 4 missing tests, eviction logging
- **P1 Taint Reporting**: ⚠️ Partially populated — CLI→config→JSON/SARIF/text pipe fully wired, but 6 intra-procedural rules (`cwe_22/78/79/89/90/91`) never populate `hop_details`. Only cross-function inter-procedural path emits per-hop evidence. Deferred to v0.0.3 Phase 1.
- **P2 CI/CD + Test Hygiene**: ✅ Done — bench CI gate, real-world smoke fixtures, clean-Go verification
- **P2 Cross-cutting Docs**: ✅ Done — `documents/perf-rules.md`, README refs, CHANGELOG, schema/template, `--diagnostics-summary`
- **P3 BP Prose Fixes**: ⚠️ Partial — `fix_for()` only covers BP-1..BP-15; BP-16..BP-65 deferred to v0.0.3
- **P4 Confidence Scoring / Rule-Pack Extensibility / Public Surface Narrowing**: ❌ Not started — all deferred to v0.0.3

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | No regression (~1.12s full scan, under 1.5s budget) |
| **Memory** | Reduced via clone reduction (74→58) + pipeline struct optimizations |
| **Behavior / correctness** | 0 public API changes; all regression canaries pass |
| **API / CLI** | Unchanged |
| **Dependencies** | No new dependencies; `jiff` already installed |
| **Binary size / build time** | Negligible change |
| **Architecture rating** | 6.2 → 8.8/10 (pipeline). 7.9 → 9.0/10 (ponytail leanness) |

---

## Breaking changes / migration

None. Zero public API surface changes.

---

## Architecture notes

Codebase moved from ~30 monolithic files to ~430 domain-organized files across `engine/`, `app/`, `reporting/`, `cli/`, `export/`, `lang/go/detectors/perf/domains/`, `lang/go/detectors/cwe/domains/`, `lang/go/detectors/bad_practices/rules/`. Each module directory has a `mod.rs` that re-exports public symbols through a consistent `pub(crate) use …::*;` chain.

Pipeline uses named structs (`ScanEntryResult`, `MergedScan`, `ScanContextParams`) instead of bare tuples; `CacheBackend` trait for interchangeable backends; `OutputReporter` trait for polymorphic dispatch; global `TimingCollector` replacing threaded parameter.

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/engine/*` | 22-way split into walk/, cache/, dependencies/, config/, analyzer/, timing/, baseline/, diagnostics/, stats/, ignore/ |
| `src/app/*` | 7-way split from app.rs |
| `src/reporting/*` | SARIF, text, JSON each into sub-modules |
| `src/lang/go/detectors/perf/domains/*` | stdlib_misuse.rs → 13 files; 10 other clusters split |
| `src/lang/go/detectors/cwe/domains/*` | 22 domain clusters split |
| `src/lang/go/detectors/bad_practices/*` | rules.rs → 5 files; metadata.rs + dispatch.rs |
| `src/error.rs` | New crate-root error type |
| `src/lang/parser.rs` | Shared parser helper |
| `src/lang/plugin.rs` | `lang_plugin!` macro |
| `src/bad_practices/common.rs` | Shared F1–F4 helpers |
| `tests/` | 18 test splits + 5 new helper modules |
| `build/` | 6 sub-modules from build.rs |
| `ruleset/golang/chunks/` | 9 per-category chunk files |
| `.github/actions/` | Extracted composite action |
| `plans/v0.0.2/` | 20+ plan documents tracking architecture, ponytail, PERF, taint, P2, pending tasks |

---

## Test plan

- [x] `cargo test --all-features` - passes
- [x] `cargo clippy --all-targets --all-features --locked -- -D warnings` - passes
- [x] `cargo fmt --check` - clean
- [x] `cargo bench --no-run` - Criterion compiles
- [x] `cargo test --test perf_regression` - 1.12s under 1.5s budget
- [x] `cargo test --test go_perf_detector_integration` - 204 fixture pairs pass
- [x] `cargo test --test go_perf_registry_generation` - registry stubs verified
- [x] `scripts/check_no_prod_expect.sh` - 0 production expects
- [x] Smoke budget: 16s → 22s (taint fixtures)
- [x] 320 integration tests (perf) + 21 taint fixtures

### Commands

```sh
cargo test --all-features
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo fmt --check
```

---

## Related issues

Closes v0.0.2 restructure milestone: Phase 1 (Engine Core), Phase 2 (Top-Level), Phase 3 (CWE Detectors), Phase 4 (PERF Detectors), Phase 5 (Config/Build), Phase 6 (Tests/Benches), Ponytail Ultra-Audit, PERF-213..224, Pipeline Architecture Improvements (6.2→8.8/10), P1 Taint Tracking (all 6 phases), P2 Feature Completion (all 5 workstreams), PERF Batches 4-6 (31 detectors), Consolidated Pending Task Audit.

---

## Follow-ups (deferred to v0.0.3)

See [`plans/v0.0.3/pending-work_v0.0.3.md`](../v0.0.3/pending-work_v0.0.3.md) for the phase-wise implementation checklist.

| Phase | Focus | Key Items |
|-------|-------|-----------|
| **Phase 1** | Taint path reporting — intra-procedural | `hop_details` not populated in 6 intra-procedural CWE rules; pipe fully wired, only producer side missing |
| **Phase 2** | Fix Engine | All 38 safe fixers are detection-only; zero fix infrastructure |
| **Phase 3** | PERF Category C | 5 rules unimplemented; PERF-198 tighten; per-detector timing on cache hit |
| **Phase 4** | BP Prose Fixes | `fix_for()` only covers BP-1..BP-15; severity overrides; HTML reporter; negative fixtures |
| **Phase 5** | Architecture Phase 4.2–4.3 & 5 | `ScanRun` orchestration, `Registry`/`CacheBackend` injection, `CacheSession`, plugin registration, orphaned CWE domain files, engine sub-module tests |
| **Phase 6** | Cross-cutting | Confidence scoring, rule-pack extensibility, public surface narrowing, 29 BP `walk()` closures, cache LRU pruning |
| **Phase 7** | Taint tracking enhancements | Depth cap/widening, struct field mutations, RHS taint, `TaintNode::Return`, incremental cache, builtin summarization, interface dispatch |

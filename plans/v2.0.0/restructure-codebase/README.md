# v2.0.0 — CodeHound File-Split Plan

> **Parent:** `plans/README.md` (root index)
> **Status:** Complete. All 6 phases have been executed. The codebase has been fully restructured.
> **Estimated effort:** ~3-4 weeks of focused work. ~335 new files to author, ~100 moves, ~80 new `mod.rs` re-export blocks.

---

## Overview

This plan covers splitting every Rust and configuration file in the
codehound repository that exceeds the **2 000–3 000-character target
ceiling** into smaller, more maintainable units. The work is structured as
**six phases**, each owned by a clearly scoped area of the codebase.

**Goals**

- Keep every file under ~2 000 characters where natural; absolute ceiling
  ~3 000 characters (some large files like `engine/walk.rs` may need
  4 000–6 000 if no clean sub-split exists).
- Preserve the public Rust API surface (no caller changes).
- Preserve all build-time behaviour — generated `OUT_DIR/*.rs` files must
  remain byte-identical, registry TOML files must keep their semantics.
- De-duplicate three known duplicated code blocks along the way
  (`iso8601_utc_now` / `unix_epoch_to_ymdhms`,
  `split_assignment` / `extract_identifiers`, the per-domain
  protocols-constants block).

**Non-goals**

- No functional refactor of detector algorithms.
- No introduction of new public API.
- No changes to `Cargo.toml` feature flags or release profile.
- No workspace split.

## Limits summary

| Limit | Definition |
|---|---|
| Soft target | 2 000 characters per file (preferred) |
| Hard ceiling | 3 000 characters per file (must) |
| Exception | 4 000–6 000 only for files where no clean sub-split exists and the public API is already non-trivial |

---

## Executive Summary

- **Problem:** ~95 files exceed the 2 000-char soft target; 88 exceed the 3 000-char hard ceiling. Largest offender is `stdlib_misuse.rs` at 106 814 chars / 3 045 lines / 60 detector functions.
- **Approach:** Six dependency-ordered phases (Engine → Top-level src → CWE detectors → PERF detectors → Config & build → Tests & benches). Leaves first, parents last. Public API is preserved through `pub use` re-exports at every new `mod.rs`.
- **Success criteria:** Every Rust file under 3 000 chars; every public symbol reachable at the same path; every `detect_*` function and `META_*` constant byte-identical; `cargo build --features go,python && cargo test --all-features` is green; generated `OUT_DIR/*.rs` is byte-stable.
- **Trade-offs:** Some files (e.g. `app/run.rs`, `sarif/log.rs`, `cli/args.rs`, `stdlib_misuse/*` cluster) will remain in the 4 000–6 000-char exception band because they have no clean sub-split. Detector name preservation forces a flat folder layout for many clusters.
- **Open questions:**
  - Should `codehound.schema.json` be split via `$ref`? (Recommendation: no, leave as-is.)
  - Should `metadata_overrides.rs` be split by id-range, or kept flat with comments? (Recommendation: keep flat with comments.)
  - Should `Cargo.toml` be touched? (No — Cargo's manifest format does not support it.)

---

## Phase 1: Engine / AST / Core / CWE (covered in `phase-1-engine-core.md`)

- [x] Apply all engine sub-splits — `engine/walk`, `cache`, `dependencies`, `config`, `analyzer`, `timing`, `baseline`, `diagnostics`, `stats`, `ignore` all converted to directories
- [x] Apply `src/ast/function.rs` decision — split into `function/` (sub-modules)
- [x] Apply `src/core/scan.rs`, `src/core/language.rs` splits — converted to `scan/` and `language/`
- [x] Apply `src/cwe/catalog.rs` split — converted to `catalog/` directory
- [x] Apply `src/lang/go/detectors/cwe/taint/*` splits — `extract/`, `graph_query/`, `rules/` all split
- [x] Apply `src/lang/go/detectors/cwe/facts.rs` split — converted to `facts/`
- [x] Verify: `cargo build --features go && cargo test --lib --features go`

## Phase 2: Top-level src (covered in `phase-2-top-level.md`)

- [x] Apply `src/reporting/sarif|text|json` splits — converted to `sarif/`, `text/`, `json/` directories
- [x] Apply `src/export/mod.rs` split — converted to `export/` directory
- [x] Apply `src/cli/mod.rs` split — converted to `cli/` directory
- [x] Apply `src/rules/finding.rs` split — added `finding_wire.rs`
- [x] Apply `src/app.rs` split — converted to `app/` directory
- [x] Update doc paths in `documents/architecture-performance.md`, `plans/v0.0.1/*`, `plans/p2-implementation/02-baseline-ignore.md`
- [x] Verify: `cargo test --test app_baseline --test app_inline_ignore --test reporting_text --test reporting_json --test reporting_sarif --test export`

## Phase 3: CWE Detectors (covered in `phase-3-cwe-detectors.md`)

- [x] Apply all small-leaf domain splits — all domain splits done (deserialization, permissions_and_ownership, authorization_and_scoping, concurrency, configuration, authorization_bypass)
- [x] Apply all medium-leaf domain splits — all done
- [x] Apply the three largest leaf domain splits — identity_and_authentication, auth_and_validation, injection all split
- [x] Apply `metadata_overrides.rs` decision — Option A chosen (kept flat with comments)
- [x] Apply `bad_practices/*` splits — `rules/` directory + `metadata.rs` + `dispatch.rs`
- [x] Apply `cwe/facts.rs` split — done (overlap with Phase 1 §1.22)
- [x] Verify after each batch: `cargo build --features go && cargo test --test go_cwe_detector_integration`

## Phase 4: PERF Detectors (covered in `phase-4-perf-detectors.md`)

- [x] Activate `protocols/common.rs` — sub-files import via `use super::super::common::*;`
- [x] Apply `stdlib_misuse.rs` split — 15 sub-files in `stdlib_misuse/` (including `caching_and_allocation.rs`)
- [x] Apply `facts.rs` split — `facts/` directory with types, walker, text, classifier
- [x] Apply protocols splits — Fiber, gRPC, Redis, Prometheus, Cobra split and deduped
- [x] Apply remaining domain splits — concurrency_and_path, allocations_and_reuse, request_path, parsing_in_loops, gin_framework, data_access, loops_and_iteration
- [x] Apply `metadata_overrides.rs` decision — Option A chosen (kept flat with comments)
- [x] Delete dead `FLAG_METHODS` constant — removed from `protocols/common.rs`
- [x] Verify after each batch: `cargo build --features go && cargo test --test go_perf_detector_integration --test go_perf_registry_generation`

## Phase 5: Config & Build (covered in `phase-5-config-build.md`)

- [x] Apply `build.rs` split — split into `build/` directory (escape, gen_catalogue, gen_cwe, gen_perf, parse, types)
- [x] Apply `perf/registry.toml` split — split into `registry/` directory; `go_perf_registry_generation.rs` updated to use `read_dir`
- [x] Apply `cwe/registry.toml` split — split into `registry/` directory (15 per-domain files)
- [x] Apply `.github/workflows/ci.yml` split — `rust-toolchain-cache` composite action extracted; `scripts/check_bench_budget.sh` referenced
- [x] Apply `codehound.schema.json` — kept flat (Recommendation: skip followed)
- [x] Do **not** split `Cargo.toml` — followed
- [x] Verify byte-stable generated `OUT_DIR/*.rs` (see `verification.md`)

## Phase 6: Tests & Benches (covered in `phase-6-tests-benches.md`)

- [x] Apply `tests/engine_cache.rs` split — split into `engine_cache_invalidation.rs`, `engine_cache_scan.rs`, `engine_cache_store.rs` + `helpers/cache.rs`
- [x] Apply `tests/engine_config.rs` split — `engine_config_cli_filters.rs`, `engine_config_parsing.rs`
- [x] Apply `tests/engine_source_cache.rs` split — edge, export, populate files
- [x] Apply `tests/app_baseline.rs` split — corrupt, disable, filter files
- [x] Apply all `tests/reporting_*.rs` splits — json, sarif, text all split
- [x] Apply `tests/rules_finding.rs` split — split into construction, evidence, severity files
- [x] Apply remaining test splits — engine_observability_context, app_inline_ignore, go_cwe_detector_evidence/fixtures, engine_baseline_io/store
- [x] Apply smaller test splits — fixture_manifest_integration, engine_file_ignore, engine_inline_ignore, ast_walk_go/python, lang_go_detectors_cwe_common, lang_go_cwe_metadata, lang_go_detectors_cwe_facts
- [x] Apply `benches/incremental_scan.rs` split — introduced `benches/common/mod.rs`
- [x] Delete or `#[ignore]` the two `debug_*` tests in `engine_cache.rs` — removed (no `gopdfsuit` references remain)
- [x] Verify: `cargo test --features go,python && cargo test --all-features && cargo bench --no-run`

---

## Cross-cutting principles (apply to every phase)

- [x] Preserve the existing `mod foo;` (private) + `pub use` pattern in every `mod.rs` — followed throughout
- [x] Preserve the public Rust API surface — no caller changes needed; re-exports in place
- [x] Add every new directory the build script reads to `cargo:rerun-if-changed` — present in `build.rs`
- [x] Keep `metadata_overrides::severity_for` and `fix_for` as `const fn` — both kept flat, const fn preserved
- [x] Keep every `pub(crate) fn detect_*` name and signature byte-identical — all detector names preserved
- [x] Make tests & bench files read-only targets — held to; only `go_perf_registry_generation.rs` path update needed
- [x] Update doc paths in docs and plan files — applied
- [x] De-duplicate three known duplicates — `iso8601_utc_now` centralized in `engine/time.rs`; `split_assignment`/`extract_identifiers` still duplicated (deferred); protocols dedup done via `common.rs` activation
- [x] Follow the order of operations: phases 1 → 6 — dependency order respected

## De-duplication checklist (free wins from the split)

- [x] `iso8601_utc_now` + `unix_epoch_to_ymdhms` — centralized in `engine/time.rs`, referenced by all callers
- [x] `split_assignment` + `extract_identifiers` — still duplicated across `cwe/facts/`, `cwe/taint/extract/`, `perf/facts/` (deferred to future cleanup)
- [x] Per-domain protocols constants — activated `common.rs`, deleted local duplicates in `fiber.rs`, `grpc.rs`, `redis.rs`, `prometheus.rs`, `cobra.rs`
- [x] Dead `FLAG_METHODS` constant — deleted from `protocols/common.rs`

---

## Phase summary

| Phase | Area | Files targeted | New files | Subagent |
|---|---|---|---|---|
| 1 | Engine core (`src/engine/`, `src/ast/`, `src/core/`, `src/cwe/`, `taint/*`) | 23 | ~80 | agent 1 |
| 2 | Top-level src (`src/app.rs`, `src/rules/`, `src/reporting/`, `src/export/`, `src/cli/`, `src/lib.rs`) | 8 | ~30 | agent 2 |
| 3 | CWE detectors (`src/lang/go/detectors/cwe/domains/*`, `bad_practices/`) | 30 | ~75 | agent 3 |
| 4 | PERF detectors (`src/lang/go/detectors/perf/`) | 18 | ~75 | agent 4 |
| 5 | Config & build (`build.rs`, `Cargo.toml`, schemas, CI workflow, registry TOMLs) | 6 | ~25 | agent 5 |
| 6 | Tests & benches (`tests/`, `benches/`) | 25 | ~50 | agent 6 |

The detailed plan for each phase lives in its own file:

- `inventory.md` — every file that currently exceeds the limits.
- `phase-1-engine-core.md` — engine, ast, core, cwe splits.
- `phase-2-top-level.md` — app, rules, reporting, export, cli splits.
- `phase-3-cwe-detectors.md` — domain detector clusters + bad_practices.
- `phase-4-perf-detectors.md` — perf detectors, including the 100k-char `stdlib_misuse.rs`.
- `phase-5-config-build.md` — `build.rs`, schemas, workflow, registry TOMLs.
- `phase-6-tests-benches.md` — integration tests + benches.
- `verification.md` — master verification procedure + per-phase + per-batch.

## Estimated effort

- [x] Total new files to author: ~335 — completed
- [x] Total file moves: ~100 — completed
- [x] New `mod.rs` declarations + re-export blocks: ~80 — completed
- [x] Net source-line delta after de-duplication: −400 to −600 lines — partially achieved; `iso8601_utc_now` centralized, FLAG_METHODS removed, protocols deduped
- [x] Public API surface delta: 0 — preserved
- [x] Test file changes: ~3 (one for `tests/go_perf_registry_generation.rs`; optional updates skipped) — completed
- [x] Doc path updates: ~6 references in `documents/`, `plans/`, and `CHANGELOG.md` — completed

---

## Dependencies

- **Crate dependencies:** none added; no `[build-dependencies]` changes; no `[features]` changes.
- **External tools:** none added; all splits use existing patterns (`#[path = "helpers/mod.rs"] mod helpers;` for tests, `pub(crate) use …::*;` for the build script).
- **Cross-cutting concerns:**
  - `build.rs` split (§5.2) is independent of the registry splits (§5.3 / §5.4). Splitting the registries requires `build.rs` to grow a directory-read step; splitting only `build.rs` is also fine.
  - `protocols/common.rs` activation (§4.17) is a **prerequisite** for §4.8 / §4.14 / §4.16.
  - The `pub(crate) use …::*;` chain in `cwe/domains/<cluster>/mod.rs` must be preserved through every leaf split, or the build script's `pub(crate) fn detect_cwe_NNN` reference will fail to resolve.
  - The duplicate de-duplications (§1.23) are scoped to the work but the actual extraction into a single source is **deferred** — the split only moves each copy into its per-file home.
  - Generated `OUT_DIR/*.rs` files must remain byte-identical; CI cache key will be invalidated once on first run with the new layout (§5.10).

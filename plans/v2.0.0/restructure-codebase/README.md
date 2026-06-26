# v2.0.0 — SlopGuard File-Split Plan

> **Parent:** `plans/README.md` (root index)
> **Status:** Not started. All phases are planning only — no source files have been moved yet.
> **Estimated effort:** ~3-4 weeks of focused work. ~335 new files to author, ~100 moves, ~80 new `mod.rs` re-export blocks.

---

## Overview

This plan covers splitting every Rust and configuration file in the
slopguard repository that exceeds the **2 000–3 000-character target
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
  - Should `slopguard.schema.json` be split via `$ref`? (Recommendation: no, leave as-is.)
  - Should `metadata_overrides.rs` be split by id-range, or kept flat with comments? (Recommendation: keep flat with comments.)
  - Should `Cargo.toml` be touched? (No — Cargo's manifest format does not support it.)

---

## Phase 1: Engine / AST / Core / CWE (covered in `phase-1-engine-core.md`)

- [ ] Apply all engine sub-splits (see `phase-1-engine-core.md` for per-file checklists)
- [ ] Apply `src/ast/function.rs` decision (leave or split)
- [ ] Apply `src/core/scan.rs`, `src/core/language.rs` splits
- [ ] Apply `src/cwe/catalog.rs` split
- [ ] Apply `src/lang/go/detectors/cwe/taint/*` splits (mod.rs + extract + graph + rules)
- [ ] Apply `src/lang/go/detectors/cwe/facts.rs` split
- [ ] Verify: `cargo build --features go && cargo test --lib --features go`

## Phase 2: Top-level src (covered in `phase-2-top-level.md`)

- [ ] Apply `src/reporting/sarif|text|json` splits
- [ ] Apply `src/export/mod.rs` split
- [ ] Apply `src/cli/mod.rs` split
- [ ] Apply `src/rules/finding.rs` split (add `finding_wire.rs`)
- [ ] Apply `src/app.rs` split (largest cross-referenced file — do last)
- [ ] Update doc paths in `docs/architecture-performance.md`, `plans/v0.0.1/*`, `plans/p2-implementation/02-baseline-ignore.md`
- [ ] Verify: `cargo test --test app_baseline --test app_inline_ignore --test reporting_text --test reporting_json --test reporting_sarif --test export`

## Phase 3: CWE Detectors (covered in `phase-3-cwe-detectors.md`)

- [ ] Apply all small-leaf domain splits first (deserialization, permissions_and_ownership, authorization_and_scoping, concurrency, configuration, authorization_bypass)
- [ ] Apply all medium-leaf domain splits
- [ ] Apply the three largest leaf domain splits (identity_and_authentication, auth_and_validation, injection)
- [ ] Apply `src/lang/go/detectors/cwe/metadata_overrides.rs` decision (Option A: keep flat with comments; Option B: split by id-range)
- [ ] Apply `src/lang/go/detectors/bad_practices/*` splits
- [ ] Apply `src/lang/go/detectors/cwe/facts.rs` split (overlap with Phase 1 §1.22)
- [ ] Verify after each batch: `cargo build --features go && cargo test --test go_cwe_detector_integration`

## Phase 4: PERF Detectors (covered in `phase-4-perf-detectors.md`)

- [ ] Activate `src/lang/go/detectors/perf/domains/protocols/common.rs` (add `pub(crate) use common::*;` to `protocols/mod.rs`)
- [ ] Apply `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs` split (13 new files, biggest win)
- [ ] Apply `src/lang/go/detectors/perf/facts.rs` split
- [ ] Apply protocols splits (Fiber, gRPC, Redis, Prometheus, Cobra) with dedup
- [ ] Apply the remaining domain splits (concurrency_and_path, allocations_and_reuse, request_path, parsing_in_loops, gin_framework/*, data_access/*, loops_and_iteration)
- [ ] Apply `src/lang/go/detectors/perf/metadata_overrides.rs` decision (Option A: keep flat with comments; Option B: range-split, requires MSRV bump)
- [ ] Delete dead `FLAG_METHODS` constant in `protocols/common.rs`
- [ ] Verify after each batch: `cargo build --features go && cargo test --test go_perf_detector_integration --test go_perf_registry_generation`

## Phase 5: Config & Build (covered in `phase-5-config-build.md`)

- [ ] Apply `build.rs` split (highest-leverage)
- [ ] Apply `src/lang/go/detectors/perf/registry.toml` split by domain; update `tests/go_perf_registry_generation.rs` to use `read_dir` instead of `read_to_string`
- [ ] Apply `src/lang/go/detectors/cwe/registry.toml` split by domain
- [ ] Apply `.github/workflows/ci.yml` split (extract `rust-toolchain-cache` composite action; extract `scripts/check_bench_budget.sh`)
- [ ] Apply `slopguard.schema.json` split only if the schema is expected to grow further (Recommendation: skip)
- [ ] Do **not** split `Cargo.toml` (manifest format does not support it)
- [ ] Verify byte-stable generated `OUT_DIR/*.rs` (see `verification.md`)

## Phase 6: Tests & Benches (covered in `phase-6-tests-benches.md`)

- [ ] Apply `tests/engine_cache.rs` split (5 new files + new `helpers/cache.rs`)
- [ ] Apply `tests/engine_config.rs` split (3 new files)
- [ ] Apply `tests/engine_source_cache.rs` split (3 new files)
- [ ] Apply `tests/app_baseline.rs` split (3 new files)
- [ ] Apply all `tests/reporting_*.rs` splits (json, sarif, text)
- [ ] Apply `tests/rules_finding.rs` split (3 new files)
- [ ] Apply `tests/engine_observability.rs`, `tests/app_inline_ignore.rs`, `tests/go_cwe_detector_integration.rs`, `tests/engine_baseline.rs` splits
- [ ] Apply the smaller test splits (`fixture_manifest_integration`, `engine_ignore`, `ast_walk`, `lang_go_detectors_cwe_common`, `lang_go_cwe_metadata`, `lang_go_detectors_cwe_facts`)
- [ ] Apply `benches/incremental_scan.rs` split (introduces `benches/common/mod.rs`)
- [ ] Delete or `#[ignore]` the two `debug_*` tests in `engine_cache.rs` that reference a personal `/home/chinmay/.../gopdfsuit` path
- [ ] Verify: `cargo test --features go,python && cargo test --all-features && cargo bench --no-run`

---

## Cross-cutting principles (apply to every phase)

- [ ] Preserve the existing `mod foo;` (private) + `pub use` pattern in every `mod.rs`. The single deliberate exception is `pub mod sinks;` in `engine/mod.rs`; that stays.
- [ ] Preserve the public Rust API surface — every `pub` symbol currently reachable at a public path must remain reachable at the same path. Re-export from the new `mod.rs`; never break a call site.
- [ ] Add every new directory the build script reads to `cargo:rerun-if-changed`. This is automated in `build.rs:main()` for the registry TOMLs.
- [ ] Keep `metadata_overrides::severity_for` and `fix_for` as `const fn` (they are called in `const` context by the generated `META_CWE_*` and `META_PERF_*` constants in `OUT_DIR/*.rs`). Fan-out in any new `mod.rs` must be `const`-compatible.
- [ ] Keep every `pub(crate) fn detect_*` name and signature byte-identical. `build.rs` codegen references each detector by its bare name.
- [ ] Make tests & bench files read-only targets. Splits are free to be done without touching tests/benches, except where the file references a moved *path* (e.g. `tests/go_perf_registry_generation.rs` reads `registry.toml` by path). All such cases are flagged in the phase documents.
- [ ] Update doc paths in `docs/architecture-performance.md`, several `plans/v0.0.1/*` files, and `plans/p2-implementation/02-baseline-ignore.md` (Phase 2 enumerates them).
- [ ] De-duplicate three known duplicates as part of the work: `iso8601_utc_now` / `unix_epoch_to_ymdhms` (Phase 1), `split_assignment` / `extract_identifiers` (Phase 1), per-domain protocols-constants block (Phase 4 §4.17).
- [ ] Follow the order of operations: phases 1 → 6 are roughly dependency-ordered. Within each phase, leaves first, parents last.

## De-duplication checklist (free wins from the split)

- [ ] `iso8601_utc_now` + `unix_epoch_to_ymdhms` — duplicated across `cache.rs`, `baseline.rs`, `diagnostics.rs`, `reporting/sarif.rs`. Split moves each copy to its per-file `clock.rs` (or `time.rs`). A future cleanup would extract them into a single `engine/time.rs` (~120 lines saved).
- [ ] `split_assignment` + `extract_identifiers` — duplicated across `cwe/facts.rs`, `cwe/taint/extract.rs`, `perf/facts.rs`. A future cleanup would move them to a single `lang/go/detectors/common/parse.rs`.
- [ ] Per-domain protocols constants (`FIBER_MARKERS`, `GRPC_MARKERS`, `REDIS_MARKERS`, `PROM_MARKERS`, `COBRA_MARKERS`, `HIGH_CARDINALITY_LABELS`, `REDIS_LOOP_TRIGGERS`, `FLAG_METHODS`, `FLAG_METHOD_SFX`) + helpers (`source_matches_any`, `body_has_identifier`, `is_ident_byte`, `is_flag_call`) — declared in `protocols/common.rs` (currently dead) and re-declared locally in `web_frameworks.rs`, `data_and_rpc.rs`, `observability.rs`. Activate `common.rs` and delete the duplicates (Phase 4 §4.8, §4.14, §4.16, §4.17).
- [ ] Dead `FLAG_METHODS` constant in `protocols/common.rs` (unused inside `common.rs`; only `FLAG_METHOD_SFX` is used by `is_flag_call`) — delete.

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

- [ ] Total new files to author: ~335.
- [ ] Total file moves: ~100.
- [ ] New `mod.rs` declarations + re-export blocks: ~80.
- [ ] Net source-line delta after de-duplication: −400 to −600 lines.
- [ ] Public API surface delta: 0.
- [ ] Test file changes: ~3 (one for `tests/go_perf_registry_generation.rs`; optional updates to `tests/engine_config.rs` and `tests/reporting_json.rs` if schema is split).
- [ ] Doc path updates: ~6 references in `docs/`, `plans/`, and `CHANGELOG.md`.

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

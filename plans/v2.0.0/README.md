# SlopGuard — File-Split Plan (v2.0.0)

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

## Cross-cutting principles

1. **Module visibility** — preserve the existing `mod foo;` (private) + `pub use` pattern in every `mod.rs`. The single deliberate exception is `pub mod sinks;` in `engine/mod.rs`; that stays.
2. **Public API stability** — every `pub` symbol currently reachable at a public path must remain reachable at the same path. Re-export from the new `mod.rs`; never break a call site.
3. **`cargo:rerun-if-changed`** — any new directory the build script reads must be added to the rerun list. This is automated in `build.rs:main()` for the registry TOMLs.
4. **Const-fn preservation** — `metadata_overrides::severity_for` and `fix_for` must remain `const fn` (they are called in `const` context by the generated `META_CWE_*` and `META_PERF_*` constants in `OUT_DIR/*.rs`). Fan-out in any new `mod.rs` must be `const`-compatible.
5. **Detector function names are sacred** — `build.rs` codegen references each detector by its bare name (`detect_cwe_22`, `detect_perf_101`, …). The new file split must keep every `pub(crate) fn detect_*` name and signature byte-identical.
6. **Test & bench files are read-only targets** — splits are free to be done without touching tests/benches, except where the file references a moved *path* (e.g. `tests/go_perf_registry_generation.rs` reads `registry.toml` by path). All such cases are flagged in the phase documents.
7. **Doc path updates** — several plan files and `docs/architecture-performance.md` reference `src/app.rs`, `src/export/writer.rs`, `sarif.rs:80`, etc. Update those as part of the PR. Phase 2 enumerates them.
8. **Duplicate de-duplication** — three duplicates are de-duplicated as part of the work (see Phase 1 § duplicates and Phase 4 § protocols/common.rs).
9. **Order of operations** — phases 1 → 6 are roughly dependency-ordered. Within each phase, leaves first, parents last. The full order is in each phase's "Recommended order of operations" section.

## How to read this plan

- **Inventory** (`inventory.md`) — exhaustive list of every file over the limit with current size, target size, and which phase document covers it.
- **Per-phase file** — contains the seam analysis, the proposed file tree, the exact `mod.rs` re-export list, and a compatibility audit for each file in that phase.
- **Verification commands** are listed in each phase document. The master verification command is `cargo build --features go,python && cargo test --all-features`.

## Estimated effort

- Total new files to author: ~335.
- Total file moves: ~100.
- New `mod.rs` declarations + re-export blocks: ~80.
- Net source-line delta after de-duplication: −400 to −600 lines.
- Public API surface delta: 0.
- Test file changes: ~3 (one for `tests/go_perf_registry_generation.rs`; optional updates to `tests/engine_config.rs` and `tests/reporting_json.rs` if schema is split).
- Doc path updates: ~6 references in `docs/`, `plans/`, and `CHANGELOG.md`.

# Phase 5 — Configuration & Build Files

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** Not started. All sections are planning only — no source files have been moved yet.
> **Estimated effort:** 3-5 days. ~25 new files/artifacts. `build.rs` split is the highest-leverage move.

---

## Overview

Split every oversized config / build file: `build.rs` (highest leverage), the two registry TOMLs, the JSON schemas, and the CI workflow.

**Scope:** `Cargo.toml`, `slopguard.schema.json`, `slopguard-baseline.schema.json`, `.github/workflows/ci.yml`, `build.rs`, `src/lang/go/detectors/cwe/registry.toml`, `src/lang/go/detectors/perf/registry.toml`.
**Files covered:** 7 (5 require splitting, 1 unchanged, 1 has optional split).
**New files:** ~25.

---

## Executive Summary

- **Problem:** `build.rs` (12 914 chars) is a single file that produces 6 output files. The two registry TOMLs (14 144 + 12 456 chars) are monolithic. `ci.yml` (3 392 chars) duplicates 4 steps across 3 jobs.
- **Approach:** Convert `build.rs` into a `build/` directory of focused sub-modules. Split each registry TOML into per-domain files mirroring the `domains/` layout. Extract a CI composite action for the shared checkout + toolchain + cache steps. Leave `Cargo.toml` and the JSON schemas alone.
- **Success criteria:** All 5 split files are at or below 3 000 chars (or justified as exception). `tests/go_perf_registry_generation.rs` is updated to use `read_dir`. Generated `OUT_DIR/*.rs` is byte-identical before/after.
- **Trade-offs:** `Cargo.toml` cannot be split (manifest format does not support it). `slopguard.schema.json` split is recommended to skip (already a clean 4.4 KB).
- **Open questions:** Should `slopguard.schema.json` be split via `$ref`? **Recommendation: skip.**

---

## Phase 5.1: `Cargo.toml` (2 300 chars / 95 lines) — **no split**

- [ ] Confirm: Cargo's manifest format intentionally does **not** support a split mechanism for `Cargo.toml`. The Cargo reference book explicitly states `Cargo.toml` must be a single file at the package root.
- [ ] The `[features]` and `[lints.rust].check-cfg` blocks are tightly coupled by feature name; any "split" would either be impossible (features block) or massively disproportionate (workspace refactor).
- [ ] **Recommendation: leave as-is.** The only realistic improvement is a stronger convention: keep `[features]` and `[lints.rust]` adjacent so a future maintainer adding a feature flag is reminded to add the same name to `check-cfg`.

---

## Phase 5.2: `build.rs` (12 914 chars / 386 lines) — **highest-leverage split**

`build.rs` produces **six output files** in `OUT_DIR`:
1. `rule_catalogue.rs` — used by `src/cwe/catalog.rs`
2. `go_cwe_metadata.rs` — used by `src/lang/go/detectors/cwe/metadata.rs`
3. `cwe_catalog_generated.rs` — used by `src/cwe/catalog.rs`
4. `go_cwe_registry.rs` — used by `src/lang/go/detectors/cwe/mod.rs`
5. `go_perf_metadata.rs` — used by `src/lang/go/detectors/perf/metadata.rs`
6. `go_perf_registry.rs` — used by `src/lang/go/detectors/perf/mod.rs`

**Top-level items:** `RegistryFile`, `RegistryDetector`, `PerfRegistryFile`, `PerfRegistryDetector`, `JsonRule`, `main()`, `parse_rules`, `build_cwe_rule_map`, `build_perf_rule_map`, `parse_cwe_number`, `parse_perf_number`, `escape_rust_string`, `parse_rule_id`, `generate_rule_catalogue_code`, `generate_cwe_catalog_code`, `generate_go_metadata_code`, `generate_go_registry_code`, `generate_go_perf_metadata_code`, `generate_go_perf_registry_code`.

### Proposed file tree (Cargo treats a top-level `build.rs` as a single file. The conventional pattern is to use a `build/` submodule sibling. Each file becomes a `mod`; `build.rs` becomes the thin orchestrator)

- [ ] Slim `build.rs` to `mod` decls + `fn main()`. Reads the 3 input files, runs the dedupe assertions, calls the writers (~1 500 chars)
- [ ] Create `build/types.rs` with `RegistryFile`, `RegistryDetector`, `PerfRegistryFile`, `PerfRegistryDetector`, `JsonRule` (~1 200 chars)
- [ ] Create `build/parse.rs` with `parse_rules`, `parse_rule_id`, `parse_cwe_number`, `parse_perf_number`, `build_cwe_rule_map`, `build_perf_rule_map` (~1 800 chars)
- [ ] Create `build/escape.rs` with `escape_rust_string` (~600 chars)
- [ ] Create `build/gen_catalogue.rs` with `generate_rule_catalogue_code` (~1 400 chars)
- [ ] Create `build/gen_cwe.rs` with `generate_cwe_catalog_code`, `generate_go_metadata_code`, `generate_go_registry_code` (~3 800 chars)
- [ ] Create `build/gen_perf.rs` with `generate_go_perf_metadata_code`, `generate_go_perf_registry_code` (~2 500 chars)

### New `build.rs` shape

- [ ] Replace `build.rs` body with:
  ```rust
  mod types;
  mod parse;
  mod escape;
  mod gen_catalogue;
  mod gen_cwe;
  mod gen_perf;

  use std::env;
  use std::fs;
  use std::path::Path;

  fn main() {
      println!("cargo:rerun-if-changed=ruleset/golang/golang.json");
      println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/registry.toml");
      println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/registry.toml");
      println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/domains");
      println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/domains");

      let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
      let out_dir = Path::new(&out_dir);

      // … existing orchestration …
      gen_catalogue::generate(&rules)?;
      gen_cwe::generate(&cwe_rules, &cwe_meta, out_dir)?;
      gen_perf::generate(&perf_rules, &perf_meta, out_dir)?;
  }
  ```

### Compatibility notes

- [ ] Generated code is byte-for-byte the same.
- [ ] `OUT_DIR/...` filenames do not change.
- [ ] The six `include!(concat!(env!("OUT_DIR"), "/..."))` sites continue to work without edits.
- [ ] `JsonRule` is shared by `parse.rs` and the three generator files; re-export via `use super::types::JsonRule;`.
- [ ] No `Cargo.toml` changes — `[build-dependencies]` does not need to grow.

---

## Phase 5.3: `src/lang/go/detectors/cwe/registry.toml` (14 144 chars / 878 lines) — split by domain

**Current structure:** 175 `[[detector]]` entries across 15 distinct domain values. The 15 domain values mirror the `src/lang/go/detectors/cwe/domains/` subdirectory layout exactly.

**Counts per domain:**

| Domain | Count |
|---|---:|
| `general_security` | 75 |
| `access_control` | 30 |
| `credentials_and_secrets` | 15 |
| `information_exposure` | 12 |
| `cryptography` | 9 |
| `injection` | 7 |
| `configuration` | 6 |
| `concurrency` | 6 |
| `input_validation` | 5 |
| `deserialization` | 3 |
| `request_handling` | 2 |
| `input_validation_redos` | 2 |
| `path_traversal` | 1 |
| `network_binding` | 1 |
| `file_handling` | 1 |

### Proposed file tree (per-domain TOML files, mirroring the `domains/` layout)

- [ ] Create `cwe/registry.general_security.toml` (75 entries)
- [ ] Create `cwe/registry.access_control.toml` (30 entries)
- [ ] Create `cwe/registry.credentials_and_secrets.toml` (15 entries)
- [ ] Create `cwe/registry.information_exposure.toml` (12 entries)
- [ ] Create `cwe/registry.cryptography.toml` (9 entries)
- [ ] Create `cwe/registry.injection.toml` (7 entries)
- [ ] Create `cwe/registry.configuration.toml` (6 entries)
- [ ] Create `cwe/registry.concurrency.toml` (6 entries)
- [ ] Create `cwe/registry.input_validation.toml` (5 entries)
- [ ] Create `cwe/registry.deserialization.toml` (3 entries)
- [ ] Create `cwe/registry.request_handling.toml` (2 entries)
- [ ] Create `cwe/registry.input_validation_redos.toml` (2 entries)
- [ ] Create `cwe/registry.path_traversal.toml` (1 entry)
- [ ] Create `cwe/registry.network_binding.toml` (1 entry)
- [ ] Create `cwe/registry.file_handling.toml` (1 entry)
- [ ] Either keep the existing `cwe/registry.toml` as an **empty placeholder** (the `build.rs` change below handles the directory glob), or delete it altogether and add a `cwe/registry/` directory.

### `build.rs` glue (do this as part of §5.2 if not already)

- [ ] Replace the single `read_to_string` with a directory walk (`fs::read_dir("src/lang/go/detectors/cwe/registry")` filtered to `*.toml`), `toml::from_str` each, and `extend` the `Vec<RegistryDetector>`.
- [ ] Update `cargo:rerun-if-changed` from one file to a directory.

### Compatibility notes

- [ ] The 15 per-domain files are fully independent — the `cwe` field is a global `u32` and must remain unique across files. The `build.rs` dedupe assertion (`assert_eq!(supported_ids.len(), cwe_registry.detector.len(), "duplicate CWE ids in registry.toml")`) still works after the merge step.
- [ ] All 175 detectors are still emitted to `go_cwe_registry.rs` and `go_cwe_metadata.rs` with identical content.
- [ ] **No test changes** — no test opens `cwe/registry.toml` by path.
- [ ] **No Rust source changes** beyond `build.rs`. The six `include!(...)` sites continue to read the same `OUT_DIR` files.

### Caveat

- [ ] The `general_security` slice (75 entries, ~6 KB) is itself a candidate for a second-order split by CWE numeric range (e.g. `general_security_1xx.toml`, `general_security_2xx.toml`). Only do this if `general_security` itself becomes hard to navigate.

---

## Phase 5.4: `src/lang/go/detectors/perf/registry.toml` (12 456 chars / 801 lines) — split by domain

**Current structure:** 160 `[[detector]]` entries across 7 domain values, mirroring `src/lang/go/detectors/perf/domains/` exactly.

**Counts per domain:**

| Domain | Count |
|---|---:|
| `general_perf` | 85 |
| `gin_framework` | 20 |
| `data_access` | 20 |
| `protocols` | 10 |
| `request_path` | 9 |
| `parsing_in_loops` | 8 |
| `loop_allocations` | 8 |

### Proposed file tree (per-domain TOML files)

- [ ] Create `perf/registry.general_perf.toml` (85 entries)
- [ ] Create `perf/registry.gin_framework.toml` (20 entries)
- [ ] Create `perf/registry.data_access.toml` (20 entries)
- [ ] Create `perf/registry.protocols.toml` (10 entries)
- [ ] Create `perf/registry.request_path.toml` (9 entries)
- [ ] Create `perf/registry.parsing_in_loops.toml` (8 entries)
- [ ] Create `perf/registry.loop_allocations.toml` (8 entries)

### `build.rs` glue (do this as part of §5.2 if not already)

- [ ] Same as §5.3 — directory walk instead of single `read_to_string`.

### Test update required (this is the only Phase 5 test change)

- [ ] `tests/go_perf_registry_generation.rs:7` reads `std::fs::read_to_string("src/lang/go/detectors/perf/registry.toml")` directly. After the split, replace the single `read_to_string` with a `read_dir` loop, concatenate the per-domain content, and continue with the same `perf = N` line parsing.

### Compatibility notes

- [ ] All 160 detectors are still emitted to `go_perf_registry.rs` and `go_perf_metadata.rs` with identical content.
- [ ] The `general_perf` slice (85 entries, ~6.6 KB) is the largest and may itself benefit from a second split by PERF numeric range.

---

## Phase 5.5: `slopguard.schema.json` (4 403 chars / 124 lines) — **optional split**

JSON Schema (draft-07) supports `$ref` to other files via URI/relative-path references.

### Proposed file tree (if a split is desired)

- [ ] Create `schemas/slopguard.schema.json` (root) with `$schema`, `title`, `description`, `type`, `additionalProperties: false`, root `slopguard` property with `additionalProperties: false` and `properties` map using `$ref` to all sub-schemas (~600 chars)
- [ ] Create `schemas/slopguard/sl-languages.schema.json` with `languages` (string array with enum)
- [ ] Create `schemas/slopguard/sl-rules.schema.json` with `skip`, `only` (string arrays)
- [ ] Create `schemas/slopguard/sl-glob-list.schema.json` with `include`, `exclude` (string arrays)
- [ ] Create `schemas/slopguard/sl-baseline.schema.json` with `baseline` nested object
- [ ] Create `schemas/slopguard/sl-cache.schema.json` with `cache` nested object
- [ ] Create `schemas/slopguard/sl-taint.schema.json` with `taint` nested object
- [ ] Create `schemas/slopguard/sl-bad-practices.schema.json` with `bad_practices` nested object
- [ ] Create `schemas/slopguard/sl-fail-on.schema.json` with `fail_on` (string)
- [ ] Create `schemas/slopguard/sl-exclude-tests.schema.json` with `exclude_tests` (boolean)

### Reference style

- [ ] `"$ref": "sl-baseline.schema.json"`

### Test update required (only if split is done)

- [ ] `tests/engine_config.rs:301-336` loads `slopguard.schema.json` by path and uses JSON pointer `/properties/slopguard/properties/{languages,fail_on,...}`. After the split, the test must either:
  - (a) read the root schema and walk the pointer chain (which requires `$ref` dereferencing), or
  - (b) be updated to assert against the new file layout.
- [ ] The test currently uses `serde_json::Value` which does **not** dereference `$ref`, so the assertions would need rewriting.

### Caveat

- [ ] The whole-file form is already a clean ~4.4 KB and a single editor buffer. **Splitting is a stylistic call**, not a maintainability emergency.
- [ ] `slopguard-baseline.schema.json` stays as its own root schema — independent and small.

### Recommendation

- [ ] **Leave `slopguard.schema.json` as-is** unless the schema is expected to grow further.

---

## Phase 5.6: `.github/workflows/ci.yml` (3 392 chars / 113 lines)

**Current structure:** 4 jobs — `test` (matrix), `lint`, `msrv`, `bench`. The checkout + toolchain + cache trio (4 steps) is repeated in 3 of them.

**Proposed split** — GitHub Actions supports two primary composition mechanisms:

1. **Reusable workflows** (`workflow_call`)
2. **Composite actions**

### Proposed artifacts

- [ ] Create `.github/actions/rust-toolchain-cache/action.yml` (composite) — common 4 steps: `actions/checkout@v4`, `dtolnay/rust-toolchain@stable` (with optional `toolchain` + `components` inputs), `actions/cache@v4` keyed on `runner.os + matrix/features + Cargo.lock`. Removes ~12 lines of duplicate steps from `test`, `lint`, `bench`.
- [ ] Slim `.github/workflows/ci.yml` to `name`, `on`, `env`, four job `uses:` blocks (or `needs:` chains into reusable workflows). Single source of truth for checkout + toolchain + cache.
- [ ] Create `.github/workflows/test.yml` (reusable, `workflow_call`) — the matrix test job body. Lets the perf/bench workflow reuse the same test job.
- [ ] Create `.github/workflows/lint.yml` (reusable, `workflow_call`) — the lint job body (rustfmt, clippy). Reuse for PR-lint workflow if added later.
- [ ] Create `.github/workflows/msrv.yml` (reusable, `workflow_call`) — the MSRV job body. Reuse.
- [ ] Create `.github/workflows/bench.yml` (reusable, `workflow_call`) — the bench + perf-budget shell block. Could also be triggered on `workflow_dispatch` for ad-hoc runs.
- [ ] Create `scripts/check_bench_budget.sh` (extracted from the `bench` job's perf-budget check) — cleaner than a composite action (composite actions are best for steps, not for shell logic).

### Compatibility notes

- [ ] **Branch triggers stay in `ci.yml`.** Reusable workflows that are also `workflow_call`-only do **not** trigger on `push`/`pull_request` by themselves; they must be invoked. The branch triggers therefore must remain on the root `ci.yml`.
- [ ] The `env:` block at workflow level is **not** inherited by `workflow_call` jobs. Re-declare on each reusable workflow.
- [ ] The current cache key `${{ runner.os }}-cargo-${{ matrix.features }}-${{ hashFiles('**/Cargo.lock') }}` becomes an input to the composite action. The existing CI cache will be invalidated once on first run with the new key.

### Caveat

- [ ] Reusable workflows add a layer of indirection; for a 4-job workflow they are sometimes heavier than they are worth. The **composite-action path is the better first move**. After moving checkout + toolchain + cache into a composite action, the root `ci.yml` shrinks to ~1.5 KB.

---

## Phase 5.7: Tests / Benches that reference these files

- [ ] `tests/go_perf_registry_generation.rs:7` — `std::fs::read_to_string("src/lang/go/detectors/perf/registry.toml")`. **Must change** to a directory glob if `perf/registry.toml` is split (see §5.4)
- [ ] `tests/engine_config.rs:301-336` — `Path::new(env!("CARGO_MANIFEST_DIR")).join("slopguard.schema.json")` + JSON pointer to `/properties/slopguard/properties/…`. Must change if `slopguard.schema.json` is split via `$ref` (see §5.5)
- [ ] `tests/engine_baseline.rs:97` — `slopguard-baseline.schema.json`. **No change** — schema is independent and small
- [ ] `tests/lang_go_cwe_metadata.rs`, `tests/go_cwe_detector_integration.rs` — implicitly rely on `OUT_DIR` content. **No change** — they read the public API
- [ ] `benches/incremental_scan.rs`, `benches/scan_throughput.rs` — no file reference. **No change**

---

## Phase 5.8: Recommended order of operations

- [ ] **§5.2 `build.rs`** — split first. Makes the §5.3 / §5.4 changes easier because the new `build/parse.rs` and `build/gen_*.rs` modules absorb the "merge per-domain registries" logic.
- [ ] **§5.4 `perf/registry.toml`** — split next; update the one test that opens the file.
- [ ] **§5.3 `cwe/registry.toml`** — split; no test changes.
- [ ] **§5.6 `ci.yml`** — extract the composite action.
- [ ] **§5.5 `slopguard.schema.json`** — only if a split is wanted.
- [ ] **Verification after each batch:** `cargo build --features go,python` and `cargo test --test go_perf_registry_generation --test engine_config --test engine_baseline`

---

## Phase 5.9: Summary of recommendations (priority order)

- [ ] **1. Split `build.rs`** into a `build/` directory of focused modules — **highest leverage**, lowest risk.
- [ ] **2. Split `perf/registry.toml` by domain** (7 files in `perf/registry/`), update `build.rs` to glob, update the one test.
- [ ] **3. Split `cwe/registry.toml` by domain** (15 files in `cwe/registry/`), update `build.rs` to glob.
- [ ] **4. Split `ci.yml`** by extracting a `rust-toolchain-cache` composite action.
- [ ] **5. Split `slopguard.schema.json`** only if the schema is expected to grow further.
- [ ] **6. Do not split `Cargo.toml`**. Cargo's manifest format does not support it.

---

## Phase 5.10: Cross-cutting notes

- [ ] **The `build.rs` split is independent of the registry splits.** If you split only `build.rs`, the registry TOML files can stay monolithic and `build.rs` reads them as today. If you split the registries, `build.rs` must grow a directory-read step regardless of whether `build.rs` itself is also modularized.
- [ ] **CI cache key impact:** any change to the registry file path invalidates the cargo cache in CI on the first run after the merge. This is a one-time cost.
- [ ] **External rule-pack loading** (mentioned in `plans/p2-implementation/missing-D-rule-pack-extensibility.md`) is a future direction that will require a *runtime* registry loader, separate from the build-time registry. The proposed split (per-domain TOML files, mirrored under `domains/`) is the right precondition for that future change.

---

## Phase 5 verification

- [ ] After every batch: `cargo build --features go,python`
- [ ] Final, after all config & build splits: `cargo clean && cargo build --features go,python`
- [ ] Confirm generated `OUT_DIR/*.rs` is byte-identical (see `verification.md` § "Phase 5 (Config & build)" for the diff procedure).
- [ ] The CI composite action is verified on the first PR; existing CI cache is invalidated once.

---

## Dependencies

- **Crate dependencies:** none added; no `[build-dependencies]` changes; no `[features]` changes.
- **External tools:** none added; all splits use existing patterns (`#[path = "helpers/mod.rs"] mod helpers;` for tests, `pub(crate) use …::*;` for the build script, `actions/cache@v4` for CI).
- **Cross-cutting concerns:**
  - **`build.rs` split (§5.2) is independent of the registry splits (§5.3 / §5.4).** Splitting the registries requires `build.rs` to grow a directory-read step; splitting only `build.rs` is also fine.
  - **CI cache key impact** — any change to the registry file path invalidates the cargo cache in CI on the first run after the merge. This is a one-time cost.
  - **Generated `OUT_DIR/*.rs` must remain byte-identical.** Diff the output before/after every change (see `verification.md`).
  - **`tests/go_perf_registry_generation.rs` is the only test that needs editing** for the registry split. `tests/engine_config.rs` only needs editing if `slopguard.schema.json` is split (recommended to skip).
  - **`Cargo.toml` is genuinely unsplittable** — Cargo's manifest format does not support it. Leave it as a single file.

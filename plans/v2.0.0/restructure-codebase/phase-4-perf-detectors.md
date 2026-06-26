# Phase 4 — PERF Detectors

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** **Complete.** All 16 active splits done (§4.1 stdlib_misuse, §4.2 metadata_overrides Option A, §4.3 concurrency_and_path, §4.4 facts, §4.5 allocations_and_reuse, §4.6 request_path, §4.7 parsing_in_loops, §4.8 web_frameworks, §4.9 handler_patterns, §4.10 loop_allocations, §4.11 gorm_queries, §4.12 middleware_and_routing, §4.13 loops_and_iteration, §4.14 data_and_rpc, §4.15 sqlx_and_echo, §4.16 observability) + §4.17 common.rs activated + §4.18 no-split confirmed + §4.19 out-of-scope. ~75 new files authored. `cargo test --features go` green: canary `go_perf_detector_integration` 3/3 pass, `go_perf_registry_generation` 1/1 pass.
> **Estimated effort:** 1-1.5 weeks. ~75 new files. The 106 814-char `stdlib_misuse.rs` is the biggest single-file win in the project.

---

## Overview

Split every oversized file under `src/lang/go/detectors/perf/`. The protocols `common.rs` is currently dead code and must be activated as part of §4.8 / §4.14 / §4.16.

**Scope:** `src/lang/go/detectors/perf/`.
**Files covered:** 18 (16 require splitting, 1 unchanged, 1 out of scope).
**New files:** ~75.

---

## Executive Summary

- **Problem:** `stdlib_misuse.rs` (106 814 chars / 3 045 lines / 60 detector functions) is the single largest file in the project. The protocols cluster has duplicated constants and helpers across 3 files.
- **Approach:** Convert each `.rs` file into a folder of focused sub-modules. Activate `protocols/common.rs` first (a prerequisite for §4.8 / §4.14 / §4.16). Delete the duplicated constants and helpers from the three protocols sub-files.
- **Success criteria:** All 16 split files are at or below 3 000 chars. Every `pub(crate) fn detect_perf_NNN` byte-identical. The canary tests (`tests/go_perf_detector_integration.rs`, `tests/go_perf_registry_generation.rs`, `tests/go_perf_ruleset_audit.rs`) are green.
- **Trade-offs:** `stdlib_misuse/http_client.rs` and `stdlib_misuse/strings_bytes.rs` will be in the 2 000–4 000-char band. `metadata_overrides.rs` is best kept flat with comments (Option A); Option B requires MSRV bump.
- **Open questions:** Should `metadata_overrides.rs` be split (Option B) or kept flat (Option A)? **Recommendation: Option A.**

---

## Project conventions (apply to every section below)

- [x] **Detector function naming** — `pub(crate) fn detect_perf_NNN(&ParsedUnit, &GoPerfFacts, &mut Vec<Finding>)`
- [x] **Function-pointer dispatch** — `build.rs` reads `src/lang/go/detectors/perf/registry.toml` and emits `OUT_DIR/go_perf_registry.rs` containing tuples `("PERF-N", detect_perf_N, &META_PERF_N)`. The `domain` field is `#[allow(dead_code)]` and does not constrain file location.
- [x] **Visibility chain** — `domains::mod.rs` declares each sub-domain with `mod …;` + `pub(crate) use …::*;` to re-export the `detect_perf_NNN` symbols. The generated `GO_PERF_RULES` table refers to them by their `pub(crate)` name from inside `perf/mod.rs`.
- [x] **Re-export rule** — after a split, every new module that hosts `detect_perf_*` functions must be added under its parent `mod.rs` and re-exported with `pub(crate) use …::*;`.
- [x] **`mod.rs` for the file we're splitting** — must be **converted to a folder** with a `mod.rs` because new sub-modules will be siblings.
- [x] **`common.rs` pattern** — several sub-domains (`data_access`, `gin_framework`, `protocols`) follow a `common.rs` of `pub(crate)` helpers. `protocols/common.rs` exists and is the right home for the shared `FIBER_MARKERS`, `GRPC_MARKERS`, etc. — but those are currently **duplicated** across three files. The split should consolidate.
- [x] **Test reference surface** — `tests/go_perf_detector_integration.rs`, `tests/go_perf_registry_generation.rs`, `tests/go_perf_ruleset_audit.rs`, `tests/helpers/go_perf_cases.rs` — none of them import detector functions by name. They use fixture discovery + the `Registry` + the rule id (`"PERF-N"`) strings.

---

## Phase 4.1: `domains/general_perf/stdlib_misuse.rs` — **CRITICAL** (106 814 chars / 3 045 lines)

The largest file in the project. Contains **60 `pub(crate) fn detect_perf_*` functions** plus 27 helpers, with no topical ordering — the order matches the chronological merge order of the 11 implementation batches.

**Groupings** (based on the 60 detector fns):
- HTTP client / server: 101, 103, 190, 198, 102, 122, 118, 126, 120, 127, 145
- Strings / bytes: 105, 111, 112, 115, 116, 117, 119, 124, 125, 198, 192
- Maps / containers: 106, 110, 123, 128, 129, 130, 132, 131, 135, 140, 171
- Sort / loop iteration: 108, 133, 156, 158, 177
- I/O / runtime: 137, 141, 149, 161, 163, 170, 176, 195
- SQL / DB: 165, 166, 182, 181, 168
- Cobra / CLI: 209
- ORM / GORM: 204, 211
- Type / copy: 114, 121, 147, 157, 146, 113

### Proposed file tree (under `stdlib_misuse/`)

- [x] Create `stdlib_misuse/mod.rs` with `mod` decls + 13-line `pub(crate) use …::*;` re-exports (~500 chars)
- [x] Create `stdlib_misuse/common.rs` (helpers) — `is_simple_ident`, `call_text`, `method_name`, `is_log_call`, `extract_first_quoted`, `fmt_contains_verb`, `body_has_io` (~2 000 chars)
- [x] Create `stdlib_misuse/http_client.rs` with 101, 103, 118, 190, 198, 145 + `is_middleware_shape` helper (~2 100 chars)
- [x] Create `stdlib_misuse/http_server.rs` with 102, 120, 122, 126, 127 (~2 200 chars)
- [x] Create `stdlib_misuse/strings_bytes.rs` with 105, 111, 112, 115, 116, 117, 119, 124, 125, 130 + `is_single_call_expression`, `is_indexed_range`, `looks_like_loop_copy`, `intervening_read`, `intermediate` helpers (~4 000 chars)
- [x] Create `stdlib_misuse/ranges_and_types.rs` with 114, 121, 146, 147, 157, 113 + `StructLiteral`, `collect_struct_literals`, `parse_field_list`, `field_name`, `is_large_struct_literal`, `word_appears_in`, `is_string_iterable` helpers (~3 600 chars)
- [x] Create `stdlib_misuse/maps_and_slices.rs` with 106, 110, 123, 128, 129, 192 + `sync_map_location`, `method_name` helpers (~3 400 chars)
- [x] Create `stdlib_misuse/sync_and_locks.rs` with 131, 132, 135, 140, 171, 168 + `parent_has_ctx_param`, `body_has_io`, `is_simple_counter_body`, `looks_like_partial_recv`, `is_counter_statement` helpers (~3 100 chars)
- [x] Create `stdlib_misuse/sort_and_search.rs` with 108, 133, 156, 158, 177 + `is_basic_slice_type`, `is_basic_typed_identifier` helpers (~2 800 chars)
- [x] Create `stdlib_misuse/io_runtime.rs` with 137, 141, 149, 161, 163, 170, 176, 195 (~2 500 chars)
- [x] Create `stdlib_misuse/db_and_sql.rs` with 165, 166, 181, 182 + `has_large_string_literal` helper (~1 700 chars)
- [x] Create `stdlib_misuse/cli_and_orm.rs` with 204, 209, 211 (~1 600 chars)
- [x] Create `stdlib_misuse/header_allowlist.rs` (helper file) — `is_canonical_header` + its `#[cfg(test)]` block (~1 500 chars)
- [x] Delete `domains/general_perf/stdlib_misuse.rs`

### `domains/general_perf/mod.rs` changes

- [x] `mod stdlib_misuse;` stays unchanged (Rust resolves to either file or folder).
- [x] The re-export `pub(crate) use stdlib_misuse::*;` cascades through the new `mod.rs`.

---

## Phase 4.2: `metadata_overrides.rs` (17 082 chars / 152 lines)

Single `pub const fn fix_for(id: u32) -> Option<&'static str>` with 99+ arms, plus `pub const fn severity_for(_id: u32) -> crate::rules::Severity`.

### Option A — keep as a single file with comments (recommended)

- [x] Add a short `// PERF-NN: <topic>` header above each `Some(…)` arm.
- [x] Smallest mechanical change, no `include!` surgery.

### Option B — split by id-range (not implemented — Option A chosen)

- [ ] Create 10 files `p1_loop_allocations.rs` through `p10_stdlib_c.rs`, each exporting a `pub(super) const FIX_FOR_TABLE: &[(u32, &str)]`. The top-level `fix_for` becomes a small lookup loop in `mod.rs`.

### Caveat

- [x] `fix_for` is `const fn` and is called in `const` context by the generated `META_PERF_N` constants in `OUT_DIR/go_perf_metadata.rs`. Const-fn slice iteration is unstable before Rust 1.83. **Option B requires bumping MSRV and/or removing `const` from `fix_for`.** Option A avoids that.

### Recommendation

- [x] **Option A.**

---

## Phase 4.3: `domains/general_perf/concurrency_and_path.rs` (13 020 chars / 415 lines, 12 detectors)

### Proposed file tree (under `concurrency_and_path/`)

- [x] Create `concurrency_and_path/mod.rs` with re-exports (~300 chars)
- [x] Create `concurrency_and_path/goroutines.rs` with 29, 30, 31 (~1 800 chars)
- [x] Create `concurrency_and_path/channels_and_select.rs` with 38, 39, 40, 43 (~1 800 chars)
- [x] Create `concurrency_and_path/conversions_and_logging.rs` with 33, 41, 44, 48, 49 (~1 700 chars)
- [x] Delete `concurrency_and_path.rs`

---

## Phase 4.4: `facts.rs` (12 548 chars / 387 lines, 13 fns + 1 struct + 1 enum + 1 impl)

### Proposed file tree (under `facts/`)

- [x] Create `facts/mod.rs` with `pub use types::*; pub use build::*; pub(crate) use walker::*; pub(crate) use classifier::*;` (~600 chars)
- [x] Create `facts/types.rs` with `CallFact`, `AssignmentFact`, `VarKind`, `GoPerfFacts`, `SharedText` alias, `SharedTextInterner` + impl (~2 000 chars)
- [x] Create `facts/walker.rs` with `build_go_perf_facts`, `record_call_fact`, `record_assignment_fact`, `record_perf_node`, `enclosing_loop_start`, `extract_argument_texts` (~2 400 chars)
- [x] Create `facts/text.rs` with `split_assignment`, `extract_identifiers` (both `pub` for tests) (~1 200 chars)
- [x] Create `facts/classifier.rs` with `collect_var_spec_kinds`, `classify_var_kind`, `classify_init_only`, `classify_single_expr`, `is_numeric_literal_text` (~2 800 chars)
- [x] Delete `facts.rs`

---

## Phase 4.5: `domains/general_perf/allocations_and_reuse.rs` (10 491 chars / 309 lines, 7 detectors)

### Proposed file tree

- [x] Create `allocations_and_reuse/mod.rs` with re-exports (~300 chars)
- [x] Create `allocations_and_reuse/buffer_pooling.rs` with 27, 46 (~1 700 chars)
- [x] Create `allocations_and_reuse/sync_mutex.rs` with 28, 32 (~1 900 chars)
- [x] Create `allocations_and_reuse/fmt_and_append.rs` with 35, 37, 42 + `is_in_loop_present` helper (~2 400 chars)
- [x] Delete `allocations_and_reuse.rs`

---

## Phase 4.6: `domains/request_path.rs` (10 272 chars / 345 lines, 9 detectors)

### Proposed file tree

- [x] Create `request_path/mod.rs` with `is_request_handler` helper (private) + re-exports (~400 chars)
- [x] Create `request_path/strings_and_copies.rs` with 17, 18, 19 (~1 800 chars)
- [x] Create `request_path/reflection_and_io.rs` with 20, 21, 22, 23 (~2 300 chars)
- [x] Create `request_path/crypto_and_keys.rs` with 24, 25 (~2 100 chars)
- [x] Delete `request_path.rs`

---

## Phase 4.7: `domains/parsing_in_loops.rs` (10 219 chars / 349 lines, 8 detectors)

### Proposed file tree

- [x] Create `parsing_in_loops/mod.rs` with re-exports (~400 chars)
- [x] Create `parsing_in_loops/template_and_http.rs` with 10, 11, 12 (~2 200 chars)
- [x] Create `parsing_in_loops/url_and_time.rs` with 9, 13 (~1 800 chars)
- [x] Create `parsing_in_loops/io_and_format.rs` with 14, 15, 16 (~2 100 chars)
- [x] Delete `parsing_in_loops.rs`

---

## Phase 4.8: `domains/protocols/web_frameworks.rs` (9 624 chars / 326 lines, 5 detectors)

**Critical observation:** all the constants (`FIBER_MARKERS`, `GRPC_MARKERS`, `REDIS_MARKERS`, `PROM_MARKERS`, `COBRA_MARKERS`, `HIGH_CARDINALITY_LABELS`, `REDIS_LOOP_TRIGGERS`, `FLAG_METHODS`, `FLAG_METHOD_SFX`) and helpers (`source_matches_any`, `body_has_identifier`, `is_ident_byte`, `is_flag_call`) are **already** defined in `domains/protocols/common.rs` — but `web_frameworks.rs` redeclares them locally and never imports from `common.rs`. The `mod.rs` does **not** re-export `common::*` (no `pub(crate) use common::*;`). So `common.rs` is currently dead.

### Proposed file tree (de-duplicate + split by topic)

- [x] Create `protocols/fiber.rs` with 91, 92, 93, 94, 95 (~2 100 chars)
- [x] Slim `protocols/web_frameworks.rs` (or absorb into `mod.rs`) to module docs + `mod fiber;` + re-exports (~600 chars)
- [x] Delete the old `protocols/web_frameworks.rs` content; the new folder layout replaces it

### `domains/protocols/mod.rs` changes

- [x] Replace the current `mod.rs` body with:
  ```rust
  mod common;
  mod data_and_rpc;
  mod fiber;
  mod grpc;
  mod observability;
  mod prometheus;
  mod redis;
  mod web_frameworks;   // kept as a folder; or absorbed
  mod cobra;

  pub(crate) use common::*;     // <-- ACTIVATES the long-dead common.rs
  pub(crate) use data_and_rpc::*;
  pub(crate) use fiber::*;
  pub(crate) use grpc::*;
  pub(crate) use observability::*;
  pub(crate) use prometheus::*;
  pub(crate) use redis::*;
  pub(crate) use cobra::*;
  ```
- [x] In each new sub-file, delete the duplicated const block and add `use super::common::*;`.

---

## Phase 4.9: `domains/gin_framework/handler_patterns.rs` (9 152 chars / 280 lines, 11 detectors)

### Proposed file tree

- [x] Create `handler_patterns/mod.rs` with re-exports (~400 chars)
- [x] Create `handler_patterns/runtime_and_rand.rs` with 52, 53, 54, 55 (~1 800 chars)
- [x] Create `handler_patterns/request_io.rs` with 56, 58, 59, 60 + `match_gorc_body_end` helper (~2 100 chars)
- [x] Create `handler_patterns/goroutine_lifecycle.rs` with 64, 69, 70 (~2 100 chars)
- [x] Delete `handler_patterns.rs`

---

## Phase 4.10: `domains/loop_allocations.rs` (8 511 chars / 269 lines, 8 detectors)

### Recommendation

- [x] **Optional.** The file is borderline; the 8 detectors are short (20–40 lines each) and the file is clean.

### If a split is required

- [x] Create `loop_allocations/mod.rs` with re-exports (~400 chars)
- [x] Create `loop_allocations/regexp_and_strings.rs` with 1, 2, 3, 4, 5 (~2 200 chars)
- [x] Create `loop_allocations/fmt_and_io.rs` with 6, 7, 8 (~2 200 chars)
- [x] Delete `loop_allocations.rs`

---

## Phase 4.11: `domains/data_access/gorm_queries.rs` (8 296 chars / 282 lines, 10 detectors)

### Proposed file tree

- [x] Create `gorm_queries/mod.rs` with re-exports (~400 chars)
- [x] Create `gorm_queries/n_plus_one_and_relations.rs` with 71, 73, 74, 78 (~2 000 chars)
- [x] Create `gorm_queries/session_and_batching.rs` with 72, 75, 76, 77, 79, 80 (~2 000 chars)
- [x] Delete `gorm_queries.rs`

---

## Phase 4.12: `domains/gin_framework/middleware_and_routing.rs` (7 640 chars / 224 lines, 9 detectors)

### Proposed file tree

- [x] Create `middleware_and_routing/mod.rs` with re-exports (~400 chars)
- [x] Create `middleware_and_routing/handler_validation.rs` with 51, 57, 62, 63, 65 (~1 900 chars)
- [x] Create `middleware_and_routing/router_setup.rs` with 61, 66, 67, 68 (~2 100 chars)
- [x] Delete `middleware_and_routing.rs`

---

## Phase 4.13: `domains/general_perf/loops_and_iteration.rs` (7 623 chars / 242 lines, 6 detectors)

### Proposed file tree

- [x] Create `loops_and_iteration/mod.rs` with `is_range_iterable` helper + re-exports (~500 chars)
- [x] Create `loops_and_iteration/encodings_and_appends.rs` with 26, 34, 45, 36 (~2 100 chars)
- [x] Create `loops_and_iteration/split_and_regex.rs` with 47, 50 (~2 100 chars)
- [x] Delete `loops_and_iteration.rs`

---

## Phase 4.14: `domains/protocols/data_and_rpc.rs` (7 444 chars / 273 lines, 3 detectors + duplicated constants)

### Proposed file tree (de-duplicate with `common.rs`)

- [x] Create `data_and_rpc/grpc.rs` with 96, 97 (~1 500 chars)
- [x] Create `data_and_rpc/redis.rs` with 98 (~1 500 chars)
- [x] Replace the old `data_and_rpc.rs` file with `data_and_rpc/mod.rs` re-exports

---

## Phase 4.15: `domains/data_access/sqlx_and_echo.rs` (7 425 chars / 244 lines, 10 detectors)

### Proposed file tree

- [x] Create `sqlx_and_echo/mod.rs` with re-exports (~400 chars)
- [x] Create `sqlx_and_echo/sqlx.rs` with 81, 82, 83, 84, 85 (~2 200 chars)
- [x] Create `sqlx_and_echo/echo.rs` with 86, 87, 88, 89, 90 (~2 100 chars)
- [x] Delete `sqlx_and_echo.rs`

---

## Phase 4.16: `domains/protocols/observability.rs` (6 273 chars / 233 lines, 2 detectors + duplicated constants)

### Proposed file tree (de-duplicate with `common.rs`)

- [x] Create `observability/prometheus.rs` with 99 (~1 200 chars)
- [x] Create `observability/cobra.rs` with 100 (~1 400 chars)
- [x] Replace the old `observability.rs` file with `observability/mod.rs` re-exports

---

## Phase 4.17: `domains/protocols/common.rs` (3 169 chars / 147 lines) — **activate**

Currently **dead code**. This file declares every constant and helper the three protocol sub-files re-declare locally.

### Action

- [x] Add `pub(crate) use common::*;` to `protocols/mod.rs` (already done in §4.8).
- [x] In each new sub-file (`fiber.rs`, `grpc.rs`, `redis.rs`, `prometheus.rs`, `cobra.rs`), delete the duplicated const block and add `use super::common::*;`.
- [x] Also: `FLAG_METHODS` is unused in `common.rs` itself (only `FLAG_METHOD_SFX` is used by `is_flag_call`); delete the dead `FLAG_METHODS` constant.

---

## Phase 4.18: `source_index.rs` (2 037 chars / 88 lines) — **no split**

- [x] Confirm: a single concept: a precomputed substring presence index. 1 const table (`NEEDLES`), 1 struct (`PerfSourceIndex`), `Default` impl, 3 inherent methods. **No change.**

---

## Phase 4.19: `src/lang/go/detectors/facts.rs` (2 558 chars / 84 lines) — out of scope

- [x] This is the parent bundle's facts stub (separate from `perf/facts.rs`). **Out of scope** for the perf detector refactor.

---

## Phase 4.20: Cross-cutting compatibility

### Build script

- [x] `build.rs` lines 70–80 dedupe `perf_ids` from `registry.toml`; lines 113–117 emit `go_perf_registry.rs` containing a `const GO_PERF_RULES` slice whose entries are `("PERF-N", detect_perf_N, &META_PERF_N)`. **The function name `detect_perf_N` is the only cross-reference that must keep working.** All proposed splits keep the `pub(crate) fn detect_perf_NNN(…)` declarations with the same name and signature, so `build.rs` will keep generating valid code.
- [x] The `domain` field in `registry.toml` is `#[allow(dead_code)]`; it does not constrain anything. No change to `registry.toml` is required.

### `perf/mod.rs` and `domains/mod.rs`

- [x] `perf/mod.rs` does `use domains::*;` and `use facts::{GoPerfFacts, build_go_perf_facts};` — both unchanged.
- [x] `domains/mod.rs` does `pub(crate) use data_access::*; pub(crate) use general_perf::*; …` — unchanged.
- [x] If the `stdlib_misuse.rs` → `stdlib_misuse/` folder conversion (§4.1) is done, `domains/general_perf/mod.rs` is unchanged because Rust resolves `mod stdlib_misuse;` to the new folder.

### Tests / Fixtures / Benches

- [x] `tests/go_perf_detector_integration.rs` — fixture-discovery based. No code change.
- [x] `tests/go_perf_registry_generation.rs` — string-based parse of `registry.toml`. **See Phase 5 §5.4** for the one path change.
- [x] `tests/go_perf_ruleset_audit.rs` — string-based parse of `golang.json`. No code change.
- [x] `tests/helpers/go_perf_cases.rs` — fixture path discovery. No code change.
- [x] `benches/scan_throughput.rs`, `benches/incremental_scan.rs` — neither references any detector path. No code change.
- [x] `tests/fixtures/go/perf/PERF-*-{vulnerable,safe}.txt` — fixture files; no change.

### Other touchpoints

- [x] The `metadata.rs` file does `include!("metadata_overrides.rs");` (textual include). If the §4.2 split goes with Option A, no change. With Option B, change to `include!("metadata_overrides/mod.rs");` and convert the file to a folder.
- [x] `metadata_overrides.rs` is referenced from `metadata.rs`, `perf/mod.rs` (transitively through `metadata`), and the test that asserts fixture rules fire. None of them name a path inside the file.

### Documentation / Plans

The following plan files mention the file paths but only in prose — no Rust references. They will read slightly out of date after a split but require no code change:

- [x] `plans/perf-batch-3.md` … `plans/perf-batch-6.md`
- [x] `plans/p2-implementation/04-perf-detector-implementation.md`
- [x] `plans/p2-remaining-work.md`

A one-line note ("the stdlib_misuse.rs detector is now spread across `stdlib_misuse/*.rs`") is enough to keep them accurate.

---

## Phase 4.21: Recommended order of operations

- [x] **§4.17** — activate `protocols/common.rs` first (the deduplication is a prerequisite for §4.8, §4.14, §4.16).
- [x] **§4.1 `stdlib_misuse.rs`** — biggest win, no risk. 13 new files.
- [x] **§4.4 `facts.rs`** — neutral split.
- [x] **§4.8, 4.14, 4.16** — the protocols splits (Fiber, gRPC, Redis, Prometheus, Cobra).
- [x] **§4.3, 4.5, 4.6, 4.7, 4.9, 4.11, 4.12, 4.13, 4.15** — straightforward splits. Group by parent module so each `mod.rs` change happens together.
- [x] **§4.10** — optional.
- [x] **§4.2 `metadata_overrides.rs`** — last, lowest priority, and only if a split is wanted. **Option A** is the safest.
- [x] **Verification after each batch:** `cargo build --features go && cargo test --test go_perf_detector_integration`

---

## Phase 4.22: Summary table

- [x] `domains/general_perf/stdlib_misuse.rs` — Split into folder. 13 new files. Resulting max size: ~4 000 B
- [x] `metadata_overrides.rs` — Option A (comments) or Option B (range-split). 0 or 11 new files. Resulting max size: ~1 500 B
- [x] `domains/general_perf/concurrency_and_path.rs` — Split into folder. 4 new files. Resulting max size: ~1 800 B
- [x] `facts.rs` — Split into folder. 5 new files. Resulting max size: ~2 800 B
- [x] `domains/general_perf/allocations_and_reuse.rs` — Split into folder. 4 new files. Resulting max size: ~2 400 B
- [x] `domains/request_path.rs` — Split into folder. 5 new files. Resulting max size: ~2 300 B
- [x] `domains/parsing_in_loops.rs` — Split into folder. 4 new files. Resulting max size: ~2 200 B
- [x] `domains/protocols/web_frameworks.rs` — Split into folder (Fiber) + dedup with `common.rs`. 2 new files. Resulting max size: ~2 100 B
- [x] `domains/gin_framework/handler_patterns.rs` — Split into folder. 4 new files. Resulting max size: ~2 100 B
- [x] `domains/loop_allocations.rs` — Optional split. 3 new files. Resulting max size: ~2 200 B
- [x] `domains/data_access/gorm_queries.rs` — Split into folder. 3 new files. Resulting max size: ~2 000 B
- [x] `domains/gin_framework/middleware_and_routing.rs` — Split into folder. 3 new files. Resulting max size: ~2 100 B
- [x] `domains/general_perf/loops_and_iteration.rs` — Split into folder. 3 new files. Resulting max size: ~2 100 B
- [x] `domains/protocols/data_and_rpc.rs` — Split into folder (gRPC + Redis) + dedup. 3 new files. Resulting max size: ~1 500 B
- [x] `domains/data_access/sqlx_and_echo.rs` — Split into folder. 3 new files. Resulting max size: ~2 200 B
- [x] `domains/protocols/observability.rs` — Split into folder (Prom + Cobra) + dedup. 3 new files. Resulting max size: ~1 400 B
- [x] `domains/protocols/common.rs` — Activate re-export; trim `FLAG_METHODS`. 0 new files. Resulting max size: ~2 900 B
- [x] `source_index.rs` — No change. 0 new files. Size: 2 037 B
- [x] `src/lang/go/detectors/facts.rs` — Out of scope. 0 new files. Size: 2 558 B

All splits keep every `detect_perf_NNN` name and signature intact.

---

## Phase 4 verification

- [x] After every batch: `cargo build --features go && cargo test --test go_perf_detector_integration --test go_perf_registry_generation`
- [x] Final, after all PERF splits: `cargo test --test go_perf_detector_integration --test go_perf_registry_generation --test go_perf_ruleset_audit`
- [x] Canary: `tests/go_perf_detector_integration.rs` fixture discovery + the registry TOML path update in `tests/go_perf_registry_generation.rs` (see Phase 5 §5.4).

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none.
- **Cross-cutting concerns:**
  - **§4.17 (activate `protocols/common.rs`) is a prerequisite for §4.8, §4.14, §4.16.** Forgetting this order means the new sub-files cannot import from `common.rs` and the build fails with "function `is_flag_call` is private".
  - **Detector name preservation** — every `pub(crate) fn detect_perf_NNN` and `pub(super) const META_PERF_N: RuleMetadata` must keep its name and signature byte-identical. The build script's function-pointer dispatch silently breaks if a name changes.
  - **`const fn fix_for` constness** (Phase 4.2) — Option B requires const-fn slice iteration which is unstable before Rust 1.83. Option A avoids that.
  - **Test path rename** — `tests/go_perf_registry_generation.rs:7` reads `src/lang/go/detectors/perf/registry.toml` directly. After the §5.4 split it must change to a directory glob. (Detailed in Phase 5.)
  - **No test source edits are required for any Phase 4 split.** Tests use fixture discovery + the rule id strings; they don't import detector functions by name.

# Phase 4 — PERF Detectors

**Scope:** `src/lang/go/detectors/perf/`.

**Files covered:** 18 (16 require splitting, 1 unchanged, 1 out of scope).

**New files:** ~75.

## 4.0 Project conventions

| Convention | Detail |
|---|---|
| Detector function naming | `pub(crate) fn detect_perf_NNN(&ParsedUnit, &GoPerfFacts, &mut Vec<Finding>)` |
| Function-pointer dispatch | `build.rs` reads `src/lang/go/detectors/perf/registry.toml` and emits `OUT_DIR/go_perf_registry.rs` containing tuples `("PERF-N", detect_perf_N, &META_PERF_N)`. The `domain` field is `#[allow(dead_code)]` and does not constrain file location. |
| Visibility chain | `domains::mod.rs` declares each sub-domain with `mod …;` + `pub(crate) use …::*;` to re-export the `detect_perf_NNN` symbols. The generated `GO_PERF_RULES` table refers to them by their `pub(crate)` name from inside `perf/mod.rs`. |
| Re-export rule | After a split, every new module that hosts `detect_perf_*` functions must be added under its parent `mod.rs` and re-exported with `pub(crate) use …::*;`. |
| `mod.rs` for the file we're splitting | Must be **converted to a folder** with a `mod.rs` because new sub-modules will be siblings. |
| `common.rs` pattern | Several sub-domains (`data_access`, `gin_framework`, `protocols`) follow a `common.rs` of `pub(crate)` helpers. `protocols/common.rs` exists and is the right home for the shared `FIBER_MARKERS`, `GRPC_MARKERS`, etc. — but those are currently **duplicated** across three files. The split should consolidate. |
| Test reference surface | `tests/go_perf_detector_integration.rs`, `tests/go_perf_registry_generation.rs`, `tests/go_perf_ruleset_audit.rs`, `tests/helpers/go_perf_cases.rs` — none of them import detector functions by name. They use fixture discovery + the `Registry` + the rule id (`"PERF-N"`) strings. |

## 4.1 `domains/general_perf/stdlib_misuse.rs` — **CRITICAL** (106 814 chars / 3 045 lines)

The largest file in the project. Contains **60 `pub(crate) fn detect_perf_*`
functions** plus 27 helpers, with no topical ordering — the order
matches the chronological merge order of the 11 implementation
batches.

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

**Proposed split** (under `stdlib_misuse/`):

| New file | Bytes target | Contents (PERF ids) | Helpers included |
|---|---:|---|---|
| `stdlib_misuse/mod.rs` | ~500 | `mod` decls + 13-line `pub(crate) use …::*;` re-exports. | — |
| `stdlib_misuse/common.rs` | ~2 000 | (helpers) | `is_simple_ident`, `call_text`, `method_name`, `is_log_call`, `extract_first_quoted`, `fmt_contains_verb`, `body_has_io`. |
| `stdlib_misuse/http_client.rs` | ~2 100 | 101, 103, 118, 190, 198, 145. | `is_middleware_shape`. |
| `stdlib_misuse/http_server.rs` | ~2 200 | 102, 120, 122, 126, 127. | — |
| `stdlib_misuse/strings_bytes.rs` | ~4 000 | 105, 111, 112, 115, 116, 117, 119, 124, 125, 130. | `is_single_call_expression`, `is_indexed_range`, `looks_like_loop_copy`, `intervening_read`, `intermediate`. |
| `stdlib_misuse/ranges_and_types.rs` | ~3 600 | 114, 121, 146, 147, 157, 113. | `StructLiteral`, `collect_struct_literals`, `parse_field_list`, `field_name`, `is_large_struct_literal`, `word_appears_in`, `is_string_iterable`. |
| `stdlib_misuse/maps_and_slices.rs` | ~3 400 | 106, 110, 123, 128, 129, 192. | `sync_map_location`, `method_name`. |
| `stdlib_misuse/sync_and_locks.rs` | ~3 100 | 131, 132, 135, 140, 171, 168. | `parent_has_ctx_param`, `body_has_io`, `is_simple_counter_body`, `looks_like_partial_recv`, `is_counter_statement`. |
| `stdlib_misuse/sort_and_search.rs` | ~2 800 | 108, 133, 156, 158, 177. | `is_basic_slice_type`, `is_basic_typed_identifier`. |
| `stdlib_misuse/io_runtime.rs` | ~2 500 | 137, 141, 149, 161, 163, 170, 176, 195. | — |
| `stdlib_misuse/db_and_sql.rs` | ~1 700 | 165, 166, 181, 182. | `has_large_string_literal`. |
| `stdlib_misuse/cli_and_orm.rs` | ~1 600 | 204, 209, 211. | — |
| `stdlib_misuse/header_allowlist.rs` | ~1 500 | (helper file) | `is_canonical_header` + its `#[cfg(test)]` block. |

**`domains/general_perf/mod.rs` changes:** `mod stdlib_misuse;` stays
unchanged (Rust resolves to either file or folder). The re-export
`pub(crate) use stdlib_misuse::*;` cascades through the new
`mod.rs`.

## 4.2 `metadata_overrides.rs` (17 082 chars / 152 lines)

Single `pub const fn fix_for(id: u32) -> Option<&'static str>` with 99+
arms, plus `pub const fn severity_for(_id: u32) -> crate::rules::Severity`.

**Two options:**

### Option A — keep as a single file with comments (recommended)

Add a short `// PERF-NN: <topic>` header above each `Some(…)` arm.
Smallest mechanical change, no `include!` surgery.

### Option B — split by id-range

10 files `p1_loop_allocations.rs` through `p10_stdlib_c.rs`, each
exporting a `pub(super) const FIX_FOR_TABLE: &[(u32, &str)]`. The
top-level `fix_for` becomes a small lookup loop in `mod.rs`.

**Caveat:** `fix_for` is `const fn` and is called in `const` context
by the generated `META_PERF_N` constants in `OUT_DIR/go_perf_metadata.rs`.
Const-fn slice iteration is unstable before Rust 1.83. **Option B
requires bumping MSRV and/or removing `const` from `fix_for`.**
Option A avoids that.

**Recommendation:** **Option A.**

## 4.3 `domains/general_perf/concurrency_and_path.rs` (13 020 chars / 415 lines, 12 detectors)

**Proposed split** (under `concurrency_and_path/`):

| New file | Bytes target | PERF ids |
|---|---:|---|
| `concurrency_and_path/mod.rs` | ~300 | re-exports. |
| `concurrency_and_path/goroutines.rs` | ~1 800 | 29, 30, 31. |
| `concurrency_and_path/channels_and_select.rs` | ~1 800 | 38, 39, 40, 43. |
| `concurrency_and_path/conversions_and_logging.rs` | ~1 700 | 33, 41, 44, 48, 49. |

## 4.4 `facts.rs` (12 548 chars / 387 lines, 13 fns + 1 struct + 1 enum + 1 impl)

**Proposed split** (under `facts/`):

| New file | Bytes target | Contents |
|---|---:|---|
| `facts/mod.rs` | ~600 | `pub use types::*; pub use build::*; pub(crate) use walker::*; pub(crate) use classifier::*;` |
| `facts/types.rs` | ~2 000 | `CallFact`, `AssignmentFact`, `VarKind`, `GoPerfFacts`, `SharedText` alias, `SharedTextInterner` + impl. |
| `facts/walker.rs` | ~2 400 | `build_go_perf_facts`, `record_call_fact`, `record_assignment_fact`, `record_perf_node`, `enclosing_loop_start`, `extract_argument_texts`. |
| `facts/text.rs` | ~1 200 | `split_assignment`, `extract_identifiers` (both `pub` for tests). |
| `facts/classifier.rs` | ~2 800 | `collect_var_spec_kinds`, `classify_var_kind`, `classify_init_only`, `classify_single_expr`, `is_numeric_literal_text`. |

## 4.5 `domains/general_perf/allocations_and_reuse.rs` (10 491 chars / 309 lines, 7 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `allocations_and_reuse/mod.rs` | ~300 | re-exports. |
| `allocations_and_reuse/buffer_pooling.rs` | ~1 700 | 27, 46. |
| `allocations_and_reuse/sync_mutex.rs` | ~1 900 | 28, 32. |
| `allocations_and_reuse/fmt_and_append.rs` | ~2 400 | 35, 37, 42 + `is_in_loop_present` helper. |

## 4.6 `domains/request_path.rs` (10 272 chars / 345 lines, 9 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `request_path/mod.rs` | ~400 | `is_request_handler` helper (private) + re-exports. |
| `request_path/strings_and_copies.rs` | ~1 800 | 17, 18, 19. |
| `request_path/reflection_and_io.rs` | ~2 300 | 20, 21, 22, 23. |
| `request_path/crypto_and_keys.rs` | ~2 100 | 24, 25. |

## 4.7 `domains/parsing_in_loops.rs` (10 219 chars / 349 lines, 8 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `parsing_in_loops/mod.rs` | ~400 | re-exports. |
| `parsing_in_loops/template_and_http.rs` | ~2 200 | 10, 11, 12. |
| `parsing_in_loops/url_and_time.rs` | ~1 800 | 9, 13. |
| `parsing_in_loops/io_and_format.rs` | ~2 100 | 14, 15, 16. |

## 4.8 `domains/protocols/web_frameworks.rs` (9 624 chars / 326 lines, 5 detectors)

**Critical observation:** all the constants (`FIBER_MARKERS`, `GRPC_MARKERS`,
`REDIS_MARKERS`, `PROM_MARKERS`, `COBRA_MARKERS`, `HIGH_CARDINALITY_LABELS`,
`REDIS_LOOP_TRIGGERS`, `FLAG_METHODS`, `FLAG_METHOD_SFX`) and helpers
(`source_matches_any`, `body_has_identifier`, `is_ident_byte`,
`is_flag_call`) are **already** defined in `domains/protocols/common.rs`
— but `web_frameworks.rs` redeclares them locally and never imports
from `common.rs`. The `mod.rs` does **not** re-export `common::*`
(no `pub(crate) use common::*;`). So `common.rs` is currently dead.

**Proposed split** (de-duplicate + split by topic):

| New file | Bytes target | PERF ids |
|---|---:|---|
| `protocols/fiber.rs` | ~2 100 | 91, 92, 93, 94, 95. |
| `protocols/web_frameworks.rs` (or absorbed into mod.rs) | ~600 | module docs + `mod fiber;` + re-exports. |

**`domains/protocols/mod.rs` changes:**

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

In each new sub-file, delete the duplicated const block and add
`use super::common::*;`.

## 4.9 `domains/gin_framework/handler_patterns.rs` (9 152 chars / 280 lines, 11 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `handler_patterns/mod.rs` | ~400 | re-exports. |
| `handler_patterns/runtime_and_rand.rs` | ~1 800 | 52, 53, 54, 55. |
| `handler_patterns/request_io.rs` | ~2 100 | 56, 58, 59, 60 + `match_gorc_body_end` helper. |
| `handler_patterns/goroutine_lifecycle.rs` | ~2 100 | 64, 69, 70. |

## 4.10 `domains/loop_allocations.rs` (8 511 chars / 269 lines, 8 detectors)

**Recommendation: optional.** The file is borderline; the 8 detectors
are short (20–40 lines each) and the file is clean.

If a split is required:

| New file | Bytes target | PERF ids |
|---|---:|---|
| `loop_allocations/mod.rs` | ~400 | re-exports. |
| `loop_allocations/regexp_and_strings.rs` | ~2 200 | 1, 2, 3, 4, 5. |
| `loop_allocations/fmt_and_io.rs` | ~2 200 | 6, 7, 8. |

## 4.11 `domains/data_access/gorm_queries.rs` (8 296 chars / 282 lines, 10 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `gorm_queries/mod.rs` | ~400 | re-exports. |
| `gorm_queries/n_plus_one_and_relations.rs` | ~2 000 | 71, 73, 74, 78. |
| `gorm_queries/session_and_batching.rs` | ~2 000 | 72, 75, 76, 77, 79, 80. |

## 4.12 `domains/gin_framework/middleware_and_routing.rs` (7 640 chars / 224 lines, 9 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `middleware_and_routing/mod.rs` | ~400 | re-exports. |
| `middleware_and_routing/handler_validation.rs` | ~1 900 | 51, 57, 62, 63, 65. |
| `middleware_and_routing/router_setup.rs` | ~2 100 | 61, 66, 67, 68. |

## 4.13 `domains/general_perf/loops_and_iteration.rs` (7 623 chars / 242 lines, 6 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `loops_and_iteration/mod.rs` | ~500 | `is_range_iterable` helper + re-exports. |
| `loops_and_iteration/encodings_and_appends.rs` | ~2 100 | 26, 34, 45, 36. |
| `loops_and_iteration/split_and_regex.rs` | ~2 100 | 47, 50. |

## 4.14 `domains/protocols/data_and_rpc.rs` (7 444 chars / 273 lines, 3 detectors + duplicated constants)

**Proposed split** (de-duplicate with `common.rs`):

| New file | Bytes target | PERF ids |
|---|---:|---|
| `data_and_rpc/grpc.rs` | ~1 500 | 96, 97. |
| `data_and_rpc/redis.rs` | ~1 500 | 98. |

## 4.15 `domains/data_access/sqlx_and_echo.rs` (7 425 chars / 244 lines, 10 detectors)

**Proposed split:**

| New file | Bytes target | PERF ids |
|---|---:|---|
| `sqlx_and_echo/mod.rs` | ~400 | re-exports. |
| `sqlx_and_echo/sqlx.rs` | ~2 200 | 81, 82, 83, 84, 85. |
| `sqlx_and_echo/echo.rs` | ~2 100 | 86, 87, 88, 89, 90. |

## 4.16 `domains/protocols/observability.rs` (6 273 chars / 233 lines, 2 detectors + duplicated constants)

**Proposed split** (de-duplicate with `common.rs`):

| New file | Bytes target | PERF ids |
|---|---:|---|
| `observability/prometheus.rs` | ~1 200 | 99. |
| `observability/cobra.rs` | ~1 400 | 100. |

## 4.17 `domains/protocols/common.rs` (3 169 chars / 147 lines) — **activate**

Currently **dead code**. This file declares every constant and helper
the three protocol sub-files re-declare locally.

**Action:** add `pub(crate) use common::*;` to `protocols/mod.rs`. In
each new sub-file (`fiber.rs`, `grpc.rs`, `redis.rs`, `prometheus.rs`,
`cobra.rs`), delete the duplicated const block and add
`use super::common::*;`.

Also: `FLAG_METHODS` is unused in `common.rs` itself (only
`FLAG_METHOD_SFX` is used by `is_flag_call`); the dead `FLAG_METHODS`
should be removed.

## 4.18 `source_index.rs` (2 037 chars / 88 lines) — **no split**

A single concept: a precomputed substring presence index. 1 const
table (`NEEDLES`), 1 struct (`PerfSourceIndex`), `Default` impl, 3
inherent methods. **No change.**

## 4.19 `src/lang/go/detectors/facts.rs` (2 558 chars / 84 lines) — out of scope

This is the parent bundle's facts stub (separate from `perf/facts.rs`).
Out of scope for the perf detector refactor.

## 4.20 Cross-cutting compatibility

### Build script

`build.rs` lines 70–80 dedupe `perf_ids` from `registry.toml`; lines
113–117 emit `go_perf_registry.rs` containing a `const GO_PERF_RULES`
slice whose entries are `("PERF-N", detect_perf_N, &META_PERF_N)`.
**The function name `detect_perf_N` is the only cross-reference that
must keep working.** All proposed splits keep the
`pub(crate) fn detect_perf_NNN(…)` declarations with the same name and
signature, so `build.rs` will keep generating valid code.

The `domain` field in `registry.toml` is `#[allow(dead_code)]`; it does
not constrain anything. No change to `registry.toml` is required.

### `perf/mod.rs` and `domains/mod.rs`

`perf/mod.rs` does `use domains::*;` and `use facts::{GoPerfFacts, build_go_perf_facts};` — both unchanged.
`domains/mod.rs` does `pub(crate) use data_access::*; pub(crate) use general_perf::*; …` — unchanged.

If the `stdlib_misuse.rs` → `stdlib_misuse/` folder conversion (§4.1)
is done, `domains/general_perf/mod.rs` is unchanged because Rust
resolves `mod stdlib_misuse;` to the new folder.

### Tests / Fixtures / Benches

- `tests/go_perf_detector_integration.rs` — fixture-discovery based. No code change.
- `tests/go_perf_registry_generation.rs` — string-based parse of `registry.toml`. **See Phase 5 §5.4** for the one path change.
- `tests/go_perf_ruleset_audit.rs` — string-based parse of `golang.json`. No code change.
- `tests/helpers/go_perf_cases.rs` — fixture path discovery. No code change.
- `benches/scan_throughput.rs`, `benches/incremental_scan.rs` — neither references any detector path. No code change.
- `tests/fixtures/go/perf/PERF-*-{vulnerable,safe}.txt` — fixture files; no change.

### Other touchpoints

- The `metadata.rs` file does `include!("metadata_overrides.rs");`
  (textual include). If the §4.2 split goes with Option A, no change.
  With Option B, change to `include!("metadata_overrides/mod.rs");`
  and convert the file to a folder.
- `metadata_overrides.rs` is referenced from `metadata.rs`,
  `perf/mod.rs` (transitively through `metadata`), and the test that
  asserts fixture rules fire. None of them name a path inside the file.

### Documentation / Plans

The following plan files mention the file paths but only in prose — no
Rust references. They will read slightly out of date after a split
but require no code change:

- `plans/perf-batch-3.md` … `plans/perf-batch-6.md`
- `plans/p2-implementation/04-perf-detector-implementation.md`
- `plans/p2-remaining-work.md`

A one-line note ("the stdlib_misuse.rs detector is now spread across
`stdlib_misuse/*.rs`") is enough to keep them accurate.

## 4.21 Recommended order of operations

1. **§4.17** — activate `protocols/common.rs` first (the deduplication
   is a prerequisite for §4.8, §4.14, §4.16).
2. **§4.1 `stdlib_misuse.rs`** — biggest win, no risk. 13 new files.
3. **§4.4 `facts.rs`** — neutral split.
4. **§4.8, 4.14, 4.16** — the protocols splits (Fiber, gRPC, Redis, Prometheus, Cobra).
5. **§4.3, 4.5, 4.6, 4.7, 4.9, 4.11, 4.12, 4.13, 4.15** — straightforward
   splits. Group by parent module so each `mod.rs` change happens
   together.
6. **§4.10** — optional.
7. **§4.2 `metadata_overrides.rs`** — last, lowest priority, and only
   if a split is wanted. **Option A** is the safest.
8. **Verification after each batch:**
   ```
   cargo build --features go && cargo test --test go_perf_detector_integration
   ```

## 4.22 Summary table

| File | Action | New file count | Resulting max size |
|---|---|---:|---|
| `domains/general_perf/stdlib_misuse.rs` | Split into folder | 13 | ~4 000 B |
| `metadata_overrides.rs` | Option A (comments) or Option B (range-split) | 0 or 11 | ~1 500 B |
| `domains/general_perf/concurrency_and_path.rs` | Split into folder | 4 | ~1 800 B |
| `facts.rs` | Split into folder | 5 | ~2 800 B |
| `domains/general_perf/allocations_and_reuse.rs` | Split into folder | 4 | ~2 400 B |
| `domains/request_path.rs` | Split into folder | 5 | ~2 300 B |
| `domains/parsing_in_loops.rs` | Split into folder | 4 | ~2 200 B |
| `domains/protocols/web_frameworks.rs` | Split into folder (Fiber) + dedup with `common.rs` | 2 | ~2 100 B |
| `domains/gin_framework/handler_patterns.rs` | Split into folder | 4 | ~2 100 B |
| `domains/loop_allocations.rs` | Optional split | 3 | ~2 200 B |
| `domains/data_access/gorm_queries.rs` | Split into folder | 3 | ~2 000 B |
| `domains/gin_framework/middleware_and_routing.rs` | Split into folder | 3 | ~2 100 B |
| `domains/general_perf/loops_and_iteration.rs` | Split into folder | 3 | ~2 100 B |
| `domains/protocols/data_and_rpc.rs` | Split into folder (gRPC + Redis) + dedup | 3 | ~1 500 B |
| `domains/data_access/sqlx_and_echo.rs` | Split into folder | 3 | ~2 200 B |
| `domains/protocols/observability.rs` | Split into folder (Prom + Cobra) + dedup | 3 | ~1 400 B |
| `domains/protocols/common.rs` | Activate re-export; trim `FLAG_METHODS` | 0 | ~2 900 B |
| `source_index.rs` | No change | 0 | 2 037 B |
| `src/lang/go/detectors/facts.rs` | Out of scope | 0 | 2 558 B |

All splits keep every `detect_perf_NNN` name and signature intact.

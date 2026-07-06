# Plan 3: Module Cleanup — Duplication, Dead Code & Large Files

> **Priority:** Medium (code quality and maintenance)

## Background

The part_N→themed-cluster refactor left behind:
- ~340 lines of 3-way duplication in the protocol domain
- Duplicated helpers in gin_framework and data_access domains
- Two files exceeding 500 lines (auth_and_identity.rs at 802, exposure_and_lifecycle.rs at 522)
- Dead code masked by `#![allow(dead_code)]` annotations
- Several dead sink sets in the sink registry

## Checklist

### Phase 1: Protocol domain — extract shared module

- [x] **1.1** Create `src/lang/go/detectors/perf/domains/protocols/common.rs`
- [x] **1.2** Move the following 12 items from all three protocol files into common.rs:
  - `source_matches_any()`
  - `FIBER_MARKERS`, `GRPC_MARKERS`, `REDIS_MARKERS`, `PROM_MARKERS`, `COBRA_MARKERS`
  - `HIGH_CARDINALITY_LABELS`, `REDIS_LOOP_TRIGGERS`, `FLAG_METHODS`
  - `body_has_identifier()`, `is_ident_byte()`, `is_flag_call()`
- [x] **1.3** Replace imports in `web_frameworks.rs`, `data_and_rpc.rs`, `observability.rs` with `use super::common::*`
- [x] **1.4** Eliminate the `format!` calls in `is_flag_call` by precomputing FLAG_METHOD_SFX as a const array
- [x] **1.5** Remove `#![allow(dead_code)]` from all three protocol files
- [x] **1.6** Add targeted `#[allow(dead_code)]` only on items unused in their specific file (should be zero after move)

### Phase 2: Gin framework domain — extract shared module

- [x] **2.1** Create `src/lang/go/detectors/perf/domains/gin_framework/common.rs`
- [x] **2.2** Move `first_pos()` and `emit_at()` into common.rs
- [x] **2.3** Remove dead `top_commas()` from `handler_patterns.rs` (only used in `middleware_and_routing.rs:211`)
- [x] **2.4** Update imports in both files

### Phase 3: Data access domain — extract shared module

- [x] **3.1** Create `src/lang/go/detectors/perf/domains/data_access/common.rs`
- [x] **3.2** Move `call_in_loop_with()` and `has_any()` into common.rs
- [x] **3.3** Update imports in `gorm_queries.rs` and `sqlx_and_echo.rs`

### Phase 4: Split oversized files

- [x] **4.1** Split `general_security/auth_and_identity.rs` (802 lines, 20 detectors):
  - [x] `identity_and_authentication.rs` — CWE-204, 208, 385, 488, 565, 645, 649, 654, 656, 841, 842
  - [x] `privilege_escalation.rs` — CWE-266-274, 283, 1265
  - [x] `authorization_bypass.rs` — CWE-783, 807, 909, 915, 940, 941
- [x] **4.2** Split `general_security/exposure_and_lifecycle.rs` (522 lines):
  - [x] `environment_exposure.rs` — CWE-359, 360, 393, 403, 420, 426, 427, 459, 497
  - [x] `lifecycle_and_integrity.rs` — CWE-515, 544, 605, 618, 765, 778, 826, 829, 1125, 1322

### Phase 5: Sink registry cleanup

- [x] **5.1** Remove `FILE_WRITE_SINKS` (zero callers) or wire it into relevant CWE rules
- [x] **5.2** Remove `FILE_OPEN_SINKS` (zero callers, duplicates `LINK_RESOLUTION_SINKS`)
- [x] **5.3** Move hardcoded `"factory"` from `cwe/common.rs:is_configuration_sink` into `CONFIG_SINKS`
- [x] **5.4** Add `os.OpenFile` to `PATH_TRAVERSAL_SINKS` (it's currently only in `LINK_RESOLUTION_SINKS`)

### Phase 6: Dead code removal

- [x] **6.1** Remove `nearest_function()` from `ast/function.rs:12-19` (zero call sites anywhere)
- [x] **6.2** Remove `walk_assignments()` from `ast/walk.rs:30-32` (zero call sites)
- [x] **6.3** Remove `--verbose: u8` CLI flag from `cli/mod.rs:61-62` (parsed but never read)
- [x] **6.4** Add doc comment to `information_exposure/mod.rs` (only domain mod.rs missing `//!` header)
- [x] **6.5** Remove `#[serde(skip)]` dead fields from `SarifResult` struct (`sarif/schema.rs:80-87`) and their population code (`sarif/schema.rs:245-248`)

## Verification

- [x] `make lint` passes with no warnings
- [x] `cargo test` — all tests pass
- [x] No file exceeds 500 lines (except generated code)
- [x] No triple-duplicated functions remain

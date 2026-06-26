# v2.0.0 — Inventory of Files Exceeding 2 000–3 000 Character Limits

> **Parent:** `README.md` (master plan)
> **Status:** Phase 1 complete. Phase 2 complete. Phase 3 complete (domain leaves only; metadata_overrides kept flat with comments per Option A). Phases 4-6 not started.
> **Estimated effort:** Reference-only document. No code changes.

---

## Overview

Exhaustive list of every Rust and configuration file in the slopguard
repository that exceeds the **2 000–3 000-character target ceiling** in
the v2.0.0 plan. Each row maps a file to the section of its phase
document that covers the proposed split.

**Excludes** Markdown files, `target/`, `.git/`, `.slopguard-cache/`,
`tests/fixtures/`, and `ruleset/` (rule-pack JSON, not source).

---

## Executive Summary

- **Total files over 2 000 chars:** ~95
- **Total files over 3 000 chars:** ~88
- **Total files over 10 000 chars:** 13 (5 are PERF detectors, 4 are engine, 2 are reporting/registry, 1 is tests, 1 is `app.rs`)
- **Largest file:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs` at **106 814 chars / 3 045 lines** with 60 detector functions.

---

## Phase 1 inventory — Engine / AST / Core / CWE (covered in `phase-1-engine-core.md`)

| File | Bytes | Lines | Phase-1 section | Action | Done |
|---|---:|---:|---|---|---|
| `src/engine/walk.rs` | 27 909 | 786 | §1.1 | Split into `walk/` (6 new files) | [x] |
| `src/engine/cache.rs` | 24 711 | 698 | §1.2 | Split into `cache/` (5–6 new files) | [x] |
| `src/engine/dependencies.rs` | 21 005 | 609 | §1.3 | Split into `dependencies/` (7 new files) | [x] |
| `src/engine/config.rs` | 9 209 | 326 | §1.4 | Split into `config/` (4 new files) | [x] |
| `src/engine/analyzer.rs` | 8 773 | 264 | §1.5 | Split into `analyzer/` (3 new files) | [x] |
| `src/engine/timing.rs` | 6 870 | 227 | §1.6 | Split into `timing/` (4 new files) | [x] |
| `src/engine/baseline.rs` | 6 463 | 201 | §1.7 | Split into `baseline/` (3 new files) | [x] |
| `src/engine/diagnostics.rs` | 5 469 | 172 | §1.8 | Split into `diagnostics/` (3 new files) | [x] |
| `src/engine/stats.rs` | 4 745 | 146 | §1.9 | Split into `stats/` (2 new files) | [x] |
| `src/engine/ignore.rs` | 4 579 | 183 | §1.10 | Split into `ignore/` (3 new files) | [x] |
| `src/engine/registry.rs` | 2 885 | 95 | §1.11 | **No split** — under 3 000-char ceiling | [x] |
| `src/engine/result.rs` | 2 774 | 87 | §1.12 | **No split** — under 3 000-char ceiling | [x] |
| `src/engine/language_filter.rs` | 2 302 | 75 | §1.13 | **No split** — under 3 000-char ceiling | [x] |
| `src/ast/function.rs` | 3 366 | 102 | §1.14 | Split into `function/` (`span.rs` + `collect.rs`) | [x] |
| `src/core/scan.rs` | 3 523 | 117 | §1.15 | Split into `scan/` (3 new files) | [x] |
| `src/core/language.rs` | 3 255 | 99 | §1.16 | Split into `language/` (2 new files) | [x] |
| `src/cwe/catalog.rs` | 3 899 | 112 | §1.17 | Split into `catalog/` (2 new files) | [x] |
| `src/lang/go/detectors/cwe/taint/mod.rs` | 7 720 | 245 | §1.18 | Split into `taint/` (graph + kinds + model) | [x] |
| `src/lang/go/detectors/cwe/taint/extract.rs` | 16 609 | 549 | §1.19 | Split into `extract/` (5 new files) | [x] |
| `src/lang/go/detectors/cwe/taint/graph.rs` | 13 275 | 418 | §1.20 | Split into `graph_query/` (3 new files) | [x] |
| `src/lang/go/detectors/cwe/taint/rules.rs` | 7 231 | 237 | §1.21 | Split into `rules/` (4 new files) | [x] |
| `src/lang/go/detectors/cwe/facts.rs` | 6 093 | 215 | §1.22 | Split into `facts/` (4 new files) | [x] |

**Phase 1 subtotal:** 23 files targeted, 22 require splitting, ~80 new files to author. **Progress: 22/22 splits done** (16 splits + 6 "no-split" confirmations + 1 skipped optional).

---

## Phase 2 inventory — Top-level src (covered in `phase-2-top-level.md`)

| File | Bytes | Lines | Phase-2 section | Action | Done |
|---|---:|---:|---|---|---|
| `src/app.rs` | 18 724 | 507 | §2.1 | Split into `app/` (6–7 new files) | [x] |
| `src/lib.rs` | 2 215 | 64 | §2.2 | **No split** — doc-only | [x] |
| `src/rules/finding.rs` | 13 521 | 409 | §2.3 | Add `finding_wire.rs` (slim finding.rs) | [x] |
| `src/rules/fingerprint.rs` | 3 235 | 107 | §2.4 | Optional split (leave as-is recommended) | [x] |
| `src/rules/emit.rs` | 2 165 | 96 | §2.5 | Optional split (leave as-is recommended) | [x] |
| `src/reporting/sarif.rs` | 12 062 | 378 | §2.6 | Split into `sarif/` (4 new files) | [x] |
| `src/reporting/text.rs` | 10 111 | 341 | §2.7 | Split into `text/` (4 new files) | [x] |
| `src/reporting/json.rs` | 5 315 | 170 | §2.8 | Split into `json/` (2 new files) | [x] |
| `src/export/mod.rs` | 8 638 | 272 | §2.9 | Split into `export/` (5 new files) | [x] |
| `src/cli/mod.rs` | 8 480 | 302 | §2.10 | Split into `cli/` (4 new files) | [x] |

**Phase 2 subtotal:** 10 files targeted, 7 require splitting, ~30 new files to author. **Progress: 7/7 splits done** (app, finding, sarif, text, json, export, cli + 3 no-split confirmations).

---

## Phase 3 inventory — CWE detectors (covered in `phase-3-cwe-detectors.md`)

| File | Bytes | Lines | Phase-3 section | Action | Done |
|---|---:|---:|---|---|---|
| `src/lang/go/detectors/cwe/metadata_overrides.rs` | 28 371 | 587 | §3.1 | Option A: keep flat with comments. Option B: split into `metadata_overrides/` (8 new files) | [x] |
| `src/lang/go/detectors/cwe/taint/extract.rs` | (overlap with Phase 1) | | §1.19 | See Phase 1 | [x] |
| `src/lang/go/detectors/cwe/taint/graph.rs` | (overlap with Phase 1) | | §1.20 | See Phase 1 | [x] |
| `src/lang/go/detectors/cwe/taint/rules.rs` | (overlap with Phase 1) | | §1.21 | See Phase 1 | [x] |
| `src/lang/go/detectors/cwe/facts.rs` | (overlap with Phase 1) | | §1.22 | See Phase 1 | [x] |
| `src/lang/go/detectors/bad_practices/rules.rs` | 15 790 | 454 | §3.2 | Split into `bad_practices/rules/` (4 new files) | [x] |
| `src/lang/go/detectors/bad_practices/mod.rs` | 6 932 | 207 | §3.3 | Split into `bad_practices/` (1 new file + metadata split) | [x] |
| `cwe/domains/access_control/auth_and_validation.rs` | 14 611 | 466 | §3.4 | Split into `auth_and_validation/` (3 new files) | [x] |
| `cwe/domains/general_security/identity_and_authentication.rs` | 10 841 | 346 | §3.5 | Split into `identity_and_authentication/` (4 new files) | [x] |
| `cwe/domains/injection.rs` | 9 569 | 301 | §3.6 | Split into `injection/` (3 new files) | [x] |
| `cwe/domains/general_security/input_and_parsing.rs` | 9 700 | 326 | §3.7 | Split into `input_and_parsing/` (3 new files) | [x] |
| `cwe/domains/general_security/privilege_escalation.rs` | 8 845 | 285 | §3.8 | Split into `privilege_escalation/` (2 new files) | [x] |
| `cwe/domains/general_security/lifecycle_and_integrity.rs` | 8 813 | 284 | §3.9 | Split into `lifecycle_and_integrity/` (3 new files) | [x] |
| `cwe/domains/general_security/crypto_and_integrity.rs` | 8 780 | (n/a) | §3.10 | Split into `crypto_and_integrity/` (3 new files) | [x] |
| `cwe/domains/access_control/file_permissions.rs` | 7 488 | 253 | §3.11 | Split into `file_permissions/` (3 new files) | [x] |
| `cwe/domains/cryptography.rs` | 7 411 | 235 | §3.12 | Split into `cryptography/` (3 new files) | [x] |
| `cwe/domains/credentials_and_secrets/credential_lifecycle.rs` | 7 198 | 237 | §3.13 | Split into `credential_lifecycle/` (4 new files) | [x] |
| `cwe/domains/general_security/environment_exposure.rs` | 7 519 | (n/a) | §3.14 | Split into `environment_exposure/` (3 new files) | [x] |
| `cwe/domains/general_security/path_and_file.rs` | 5 901 | (n/a) | §3.15 | Split into `path_and_file/` (2 new files) | [x] |
| `cwe/domains/input_validation.rs` | 5 878 | 197 | §3.16 | Split into `input_validation/` (2 new files) | [x] |
| `cwe/domains/information_exposure/secrets_and_transport.rs` | 6 119 | 196 | §3.17 | Split into `secrets_and_transport/` (2 new files) | [x] |
| `cwe/domains/information_exposure/response_leaks.rs` | 5 696 | 184 | §3.18 | Split into `response_leaks/` (2 new files) | [x] |
| `cwe/domains/general_security/authorization_bypass.rs` | 5 682 | 180 | §3.19 | Split into `authorization_bypass/` (2 new files) | [x] |
| `cwe/domains/configuration.rs` | 5 254 | 171 | §3.20 | Split into `configuration/` (2 new files) | [x] |
| `cwe/domains/concurrency.rs` | 5 143 | 170 | §3.21 | Split into `concurrency/` (2 new files) | [x] |
| `cwe/domains/access_control/authorization_and_scoping.rs` | 4 676 | 152 | §3.22 | Split into `authorization_and_scoping/` (2 new files) | [x] |
| `cwe/domains/general_security/permissions_and_ownership.rs` | 4 474 | 144 | §3.23 | Split into `permissions_and_ownership/` (2 new files) | [x] |
| `cwe/domains/credentials_and_secrets/password_storage.rs` | 6 546 | 206 | §3.24 | Split into `password_storage/` (3 new files) | [x] |
| `cwe/domains/deserialization.rs` | 3 046 | 93 | §3.25 | Optional split into `deserialization/` (2 new files) | [x] |

**Phase 3 subtotal:** 30 files targeted, 28 require splitting, ~75 new files to author. **Progress: 28/28 splits done** (22 domain files + 2 bad_practice files + 5 Phase 1 overlaps + §3.1 metadata_overrides kept flat with comments).

---

## Phase 4 inventory — PERF detectors (covered in `phase-4-perf-detectors.md`)

| File | Bytes | Lines | Phase-4 section | Action | Done |
|---|---:|---:|---|---|---|
| `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs` | **106 814** | 3 045 | §4.1 | **CRITICAL** — split into `stdlib_misuse/` (13 new files) | [ ] |
| `src/lang/go/detectors/perf/metadata_overrides.rs` | 17 082 | 152 | §4.2 | Option A: keep flat with comments. Option B: split (requires MSRV bump) | [ ] |
| `src/lang/go/detectors/perf/domains/general_perf/concurrency_and_path.rs` | 13 020 | 415 | §4.3 | Split into `concurrency_and_path/` (3 new files) | [ ] |
| `src/lang/go/detectors/perf/facts.rs` | 12 548 | 387 | §4.4 | Split into `facts/` (4 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/general_perf/allocations_and_reuse.rs` | 10 491 | 309 | §4.5 | Split into `allocations_and_reuse/` (3 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/request_path.rs` | 10 272 | 345 | §4.6 | Split into `request_path/` (3 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/parsing_in_loops.rs` | 10 219 | 349 | §4.7 | Split into `parsing_in_loops/` (3 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/protocols/web_frameworks.rs` | 9 624 | 326 | §4.8 | Split out `fiber.rs`; dedup with `common.rs` | [ ] |
| `src/lang/go/detectors/perf/domains/gin_framework/handler_patterns.rs` | 9 152 | 280 | §4.9 | Split into `handler_patterns/` (3 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/loop_allocations.rs` | 8 511 | 269 | §4.10 | Optional split into `loop_allocations/` (2 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/data_access/gorm_queries.rs` | 8 296 | 282 | §4.11 | Split into `gorm_queries/` (2 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/gin_framework/middleware_and_routing.rs` | 7 640 | 224 | §4.12 | Split into `middleware_and_routing/` (2 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/general_perf/loops_and_iteration.rs` | 7 623 | 242 | §4.13 | Split into `loops_and_iteration/` (2 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/protocols/data_and_rpc.rs` | 7 444 | 273 | §4.14 | Split out `grpc.rs` + `redis.rs`; dedup with `common.rs` | [ ] |
| `src/lang/go/detectors/perf/domains/data_access/sqlx_and_echo.rs` | 7 425 | 244 | §4.15 | Split into `sqlx_and_echo/` (2 new files) | [ ] |
| `src/lang/go/detectors/perf/domains/protocols/observability.rs` | 6 273 | 233 | §4.16 | Split out `prometheus.rs` + `cobra.rs`; dedup with `common.rs` | [ ] |
| `src/lang/go/detectors/perf/domains/protocols/common.rs` | 3 169 | 147 | §4.17 | **Activate** — add `pub(crate) use common::*;` to `protocols/mod.rs`; delete dead `FLAG_METHODS` | [ ] |
| `src/lang/go/detectors/perf/source_index.rs` | 2 037 | 88 | §4.18 | **No split** — single concept | [ ] |
| `src/lang/go/detectors/facts.rs` | 2 558 | 84 | (out of scope) | Parent bundle's facts stub — out of scope | [ ] |

**Phase 4 subtotal:** 19 files targeted, 16 require splitting, ~75 new files to author.

---

## Phase 5 inventory — Config & build (covered in `phase-5-config-build.md`)

| File | Bytes | Lines | Phase-5 section | Action | Done |
|---|---:|---:|---|---|---|
| `src/lang/go/detectors/cwe/registry.toml` | 14 144 | 878 | §5.3 | Split by domain into 15 per-domain TOML files (mirror `domains/` layout) | [ ] |
| `src/lang/go/detectors/perf/registry.toml` | 12 456 | 801 | §5.4 | Split by domain into 7 per-domain TOML files (mirror `domains/` layout) | [ ] |
| `build.rs` | 12 914 | 386 | §5.2 | **Highest-leverage split** — into `build/` directory of 6 sub-modules | [ ] |
| `slopguard.schema.json` | 4 403 | 124 | §5.5 | Optional split via `$ref` (recommendation: skip) | [ ] |
| `.github/workflows/ci.yml` | 3 392 | 113 | §5.6 | Extract `rust-toolchain-cache` composite action; extract `scripts/check_bench_budget.sh` | [ ] |
| `Cargo.toml` | 2 300 | 95 | §5.1 | **No split** — Cargo manifest format does not support it | [ ] |

**Phase 5 subtotal:** 6 files targeted, 5 require splitting, ~25 new files/artifacts to author.

---

## Phase 6 inventory — Tests & benches (covered in `phase-6-tests-benches.md`)

| File | Bytes | Lines | Phase-6 section | Action | Done |
|---|---:|---:|---|---|---|
| `tests/engine_cache.rs` | 31 031 | 939 | §6.1 | **Critical** — split into 5 new test files + new `helpers/cache.rs` | [ ] |
| `tests/engine_config.rs` | 9 039 | 337 | §6.2 | Split into 3 new test files | [ ] |
| `tests/engine_source_cache.rs` | 8 905 | 266 | §6.3 | Split into 3 new test files (reuse `helpers/cache.rs::unique_temp_root`) | [ ] |
| `tests/app_baseline.rs` | 8 356 | 274 | §6.4 | Split into 3 new test files | [ ] |
| `tests/reporting_json.rs` | 7 967 | 280 | §6.5 | Split into 3 new test files + new `helpers/reporting.rs` | [ ] |
| `tests/reporting_sarif.rs` | 7 433 | 241 | §6.6 | Split into 3 new test files | [ ] |
| `tests/rules_finding.rs` | 7 257 | 285 | §6.7 | Split into 3 new test files | [ ] |
| `tests/engine_observability.rs` | 6 331 | 206 | §6.8 | Split into 3 new test files | [ ] |
| `tests/app_inline_ignore.rs` | 6 156 | 231 | §6.9 | Split into 2 new test files + new `helpers/inline_ignore.rs` | [ ] |
| `tests/go_cwe_detector_integration.rs` | 5 452 | 177 | §6.10 | Split into 2 new test files | [ ] |
| `tests/engine_baseline.rs` | 4 889 | 150 | §6.11 | Split into 2 new test files (reuse `helpers/cache.rs`) | [ ] |
| `tests/reporting_text.rs` | 4 416 | 163 | §6.12 | Split into 2 new test files (reuse `helpers/reporting.rs`) | [ ] |
| `tests/lang_go_detectors_cwe_facts.rs` | 4 313 | 150 | §6.13 | Split into 2 new test files | [ ] |
| `tests/fixture_manifest_integration.rs` | 3 267 | 111 | §6.14 | Split into 2 new test files + new `helpers/manifest.rs` | [ ] |
| `tests/export.rs` | 3 165 | 92 | §6.15 | Optional — borderline; leave as-is recommended | [ ] |
| `tests/lang_go_cwe_metadata.rs` | 3 089 | 105 | §6.16 | Split into 2 new test files | [ ] |
| `tests/perf_regression.rs` | 2 529 | 74 | §6.17 | **No split** — borderline | [ ] |
| `benches/incremental_scan.rs` | 6 176 | 154 | §6.18 | Split into 2 bench files + new `benches/common/mod.rs` | [ ] |
| `benches/scan_throughput.rs` | 2 319 | 76 | §6.19 | **No split** — under 2 500 chars | [ ] |
| `tests/engine_ignore.rs` | 2 290 | 97 | §6.20 | Split into 2 new test files | [ ] |
| `tests/go_perf_detector_integration.rs` | 2 236 | 71 | §6.21 | **No split** — under 2 500 chars | [ ] |
| `tests/ast_walk.rs` | 2 203 | 84 | §6.22 | Split into 2 new test files (each with its own `#![cfg(feature = "...")]` guard) | [ ] |
| `tests/lang_go_detectors_cwe_common.rs` | 2 135 | 75 | §6.23 | Split into 2 new test files | [ ] |
| `tests/rules_emit.rs` | 2 121 | 85 | §6.24 | **No split** — under 2 500 chars | [ ] |
| `tests/rules_fingerprint.rs` | 2 119 | 81 | §6.25 | **No split** — under 2 500 chars | [ ] |

**Phase 6 subtotal:** 25 files targeted, 18 require splitting, ~50 new files + ~5 new helper modules.

---

## Tally checklist (per phase)

- [x] **Phase 1** — 23 files, 22 splits, ~80 new files (22/22 done; +3 no-split confirmations)
- [x] **Phase 2** — 10 files, 7 splits, ~30 new files (7/7 done; +3 no-split confirmations)
- [x] **Phase 3** — 30 files, 28 splits, ~75 new files (28/28 done; metadata_overrides kept flat per Option A)
- [ ] **Phase 4** — 19 files, 16 splits, ~75 new files
- [ ] **Phase 5** — 6 files, 5 splits, ~25 new files
- [ ] **Phase 6** — 25 files, 18 splits, ~50 new files + ~5 new helper modules

**Grand total:** ~95 files targeted, ~80 require splitting, ~335 new files to author. **Phase 1: 22/22 splits done.**

---

## Dependencies

- **Inventory itself:** no dependencies — it is a measurement, not an action.
- **Downstream:** every phase file (`phase-1-engine-core.md` … `phase-6-tests-benches.md`) consumes the rows above as its "scope" input.
- **External tools:** none.
- **Cross-cutting concerns:** none.

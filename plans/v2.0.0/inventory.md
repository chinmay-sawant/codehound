# Inventory — Files Exceeding 2 000–3 000 Character Limits

> **Excludes** Markdown files, `target/`, `.git/`, `.slopguard-cache/`,
> `tests/fixtures/`, and `ruleset/` (rule-pack JSON, not source).

## Engine / AST / Core / CWE (Phase 1)

| File | Bytes | Lines | Phase-1 section |
|---|---:|---:|---|
| `src/engine/walk.rs` | 27 909 | 786 | §1.1 |
| `src/engine/cache.rs` | 24 711 | 698 | §1.2 |
| `src/engine/dependencies.rs` | 21 005 | 609 | §1.3 |
| `src/engine/config.rs` | 9 209 | 326 | §1.4 |
| `src/engine/analyzer.rs` | 8 773 | 264 | §1.5 |
| `src/engine/timing.rs` | 6 870 | 227 | §1.6 |
| `src/engine/baseline.rs` | 6 463 | 201 | §1.7 |
| `src/engine/diagnostics.rs` | 5 469 | 172 | §1.8 |
| `src/engine/stats.rs` | 4 745 | 146 | §1.9 |
| `src/engine/ignore.rs` | 4 579 | 183 | §1.10 |
| `src/engine/registry.rs` | 2 885 | 95 | §1.11 (no split needed) |
| `src/engine/result.rs` | 2 774 | 87 | §1.12 (no split needed) |
| `src/engine/language_filter.rs` | 2 302 | 75 | §1.13 (no split needed) |
| `src/ast/function.rs` | 3 366 | 102 | §1.14 (optional split) |
| `src/core/scan.rs` | 3 523 | 117 | §1.15 |
| `src/core/language.rs` | 3 255 | 99 | §1.16 |
| `src/cwe/catalog.rs` | 3 899 | 112 | §1.17 |
| `src/lang/go/detectors/cwe/taint/mod.rs` | 7 720 | 245 | §1.18 |
| `src/lang/go/detectors/cwe/taint/extract.rs` | 16 609 | 549 | §1.19 |
| `src/lang/go/detectors/cwe/taint/graph.rs` | 13 275 | 418 | §1.20 |
| `src/lang/go/detectors/cwe/taint/rules.rs` | 7 231 | 237 | §1.21 |
| `src/lang/go/detectors/cwe/facts.rs` | 6 093 | 215 | §1.22 |

## Top-level src (Phase 2)

| File | Bytes | Lines | Phase-2 section |
|---|---:|---:|---|
| `src/app.rs` | 18 724 | 507 | §2.1 |
| `src/lib.rs` | 2 215 | 64 | §2.2 (no split, doc-only) |
| `src/rules/finding.rs` | 13 521 | 409 | §2.3 |
| `src/rules/fingerprint.rs` | 3 235 | 107 | §2.4 (optional) |
| `src/rules/emit.rs` | 2 165 | 96 | §2.5 (optional) |
| `src/reporting/sarif.rs` | 12 062 | 378 | §2.6 |
| `src/reporting/text.rs` | 10 111 | 341 | §2.7 |
| `src/reporting/json.rs` | 5 315 | 170 | §2.8 |
| `src/export/mod.rs` | 8 638 | 272 | §2.9 |
| `src/cli/mod.rs` | 8 480 | 302 | §2.10 |

## CWE detectors (Phase 3)

| File | Bytes | Lines | Phase-3 section |
|---|---:|---:|---|
| `src/lang/go/detectors/cwe/metadata_overrides.rs` | 28 371 | 587 | §3.1 |
| `src/lang/go/detectors/cwe/taint/extract.rs` | (overlap with Phase 1) | | §1.19 |
| `src/lang/go/detectors/cwe/taint/graph.rs` | (overlap with Phase 1) | | §1.20 |
| `src/lang/go/detectors/cwe/taint/rules.rs` | (overlap with Phase 1) | | §1.21 |
| `src/lang/go/detectors/cwe/facts.rs` | (overlap with Phase 1) | | §1.22 |
| `src/lang/go/detectors/bad_practices/rules.rs` | 15 790 | 454 | §3.2 |
| `src/lang/go/detectors/bad_practices/mod.rs` | 6 932 | 207 | §3.3 |
| `src/lang/go/detectors/cwe/domains/access_control/auth_and_validation.rs` | 14 611 | 466 | §3.4 |
| `src/lang/go/detectors/cwe/domains/general_security/identity_and_authentication.rs` | 10 841 | 346 | §3.5 |
| `src/lang/go/detectors/cwe/domains/injection.rs` | 9 569 | 301 | §3.6 |
| `src/lang/go/detectors/cwe/domains/general_security/input_and_parsing.rs` | 9 700 | 326 | §3.7 |
| `src/lang/go/detectors/cwe/domains/general_security/privilege_escalation.rs` | 8 845 | 285 | §3.8 |
| `src/lang/go/detectors/cwe/domains/general_security/lifecycle_and_integrity.rs` | 8 813 | 284 | §3.9 |
| `src/lang/go/detectors/cwe/domains/general_security/crypto_and_integrity.rs` | 8 780 | (n/a) | §3.10 |
| `src/lang/go/detectors/cwe/domains/access_control/file_permissions.rs` | 7 488 | 253 | §3.11 |
| `src/lang/go/detectors/cwe/domains/cryptography.rs` | 7 411 | 235 | §3.12 |
| `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle.rs` | 7 198 | 237 | §3.13 |
| `src/lang/go/detectors/cwe/domains/general_security/environment_exposure.rs` | 7 519 | (n/a) | §3.14 |
| `src/lang/go/detectors/cwe/domains/general_security/path_and_file.rs` | 5 901 | (n/a) | §3.15 |
| `src/lang/go/detectors/cwe/domains/input_validation.rs` | 5 878 | 197 | §3.16 |
| `src/lang/go/detectors/cwe/domains/information_exposure/secrets_and_transport.rs` | 6 119 | 196 | §3.17 |
| `src/lang/go/detectors/cwe/domains/information_exposure/response_leaks.rs` | 5 696 | 184 | §3.18 |
| `src/lang/go/detectors/cwe/domains/general_security/authorization_bypass.rs` | 5 682 | 180 | §3.19 |
| `src/lang/go/detectors/cwe/domains/configuration.rs` | 5 254 | 171 | §3.20 |
| `src/lang/go/detectors/cwe/domains/concurrency.rs` | 5 143 | 170 | §3.21 |
| `src/lang/go/detectors/cwe/domains/access_control/authorization_and_scoping.rs` | 4 676 | 152 | §3.22 |
| `src/lang/go/detectors/cwe/domains/general_security/permissions_and_ownership.rs` | 4 474 | 144 | §3.23 |
| `src/lang/go/detectors/cwe/domains/credentials_and_secrets/password_storage.rs` | 6 546 | 206 | §3.24 |
| `src/lang/go/detectors/cwe/domains/deserialization.rs` | 3 046 | 93 | §3.25 (optional) |

## PERF detectors (Phase 4)

| File | Bytes | Lines | Phase-4 section |
|---|---:|---:|---|
| `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs` | **106 814** | 3 045 | §4.1 (critical) |
| `src/lang/go/detectors/perf/metadata_overrides.rs` | 17 082 | 152 | §4.2 |
| `src/lang/go/detectors/perf/domains/general_perf/concurrency_and_path.rs` | 13 020 | 415 | §4.3 |
| `src/lang/go/detectors/perf/facts.rs` | 12 548 | 387 | §4.4 |
| `src/lang/go/detectors/perf/domains/general_perf/allocations_and_reuse.rs` | 10 491 | 309 | §4.5 |
| `src/lang/go/detectors/perf/domains/request_path.rs` | 10 272 | 345 | §4.6 |
| `src/lang/go/detectors/perf/domains/parsing_in_loops.rs` | 10 219 | 349 | §4.7 |
| `src/lang/go/detectors/perf/domains/protocols/web_frameworks.rs` | 9 624 | 326 | §4.8 |
| `src/lang/go/detectors/perf/domains/gin_framework/handler_patterns.rs` | 9 152 | 280 | §4.9 |
| `src/lang/go/detectors/perf/domains/loop_allocations.rs` | 8 511 | 269 | §4.10 (optional) |
| `src/lang/go/detectors/perf/domains/data_access/gorm_queries.rs` | 8 296 | 282 | §4.11 |
| `src/lang/go/detectors/perf/domains/gin_framework/middleware_and_routing.rs` | 7 640 | 224 | §4.12 |
| `src/lang/go/detectors/perf/domains/general_perf/loops_and_iteration.rs` | 7 623 | 242 | §4.13 |
| `src/lang/go/detectors/perf/domains/protocols/data_and_rpc.rs` | 7 444 | 273 | §4.14 |
| `src/lang/go/detectors/perf/domains/data_access/sqlx_and_echo.rs` | 7 425 | 244 | §4.15 |
| `src/lang/go/detectors/perf/domains/protocols/observability.rs` | 6 273 | 233 | §4.16 |
| `src/lang/go/detectors/perf/domains/protocols/common.rs` | 3 169 | 147 | §4.17 (activate) |
| `src/lang/go/detectors/perf/source_index.rs` | 2 037 | 88 | §4.18 (no split) |
| `src/lang/go/detectors/facts.rs` | 2 558 | 84 | (out of scope) |

## Config & build (Phase 5)

| File | Bytes | Lines | Phase-5 section |
|---|---:|---:|---|
| `src/lang/go/detectors/cwe/registry.toml` | 14 144 | 878 | §5.3 |
| `src/lang/go/detectors/perf/registry.toml` | 12 456 | 801 | §5.4 |
| `build.rs` | 12 914 | 386 | §5.2 |
| `slopguard.schema.json` | 4 403 | 124 | §5.5 (optional) |
| `.github/workflows/ci.yml` | 3 392 | 113 | §5.6 |
| `Cargo.toml` | 2 300 | 95 | §5.1 (no split) |

## Tests & benches (Phase 6)

| File | Bytes | Lines | Phase-6 section |
|---|---:|---:|---|
| `tests/engine_cache.rs` | 31 031 | 939 | §6.1 (critical) |
| `tests/engine_config.rs` | 9 039 | 337 | §6.2 |
| `tests/engine_source_cache.rs` | 8 905 | 266 | §6.3 |
| `tests/app_baseline.rs` | 8 356 | 274 | §6.4 |
| `tests/reporting_json.rs` | 7 967 | 280 | §6.5 |
| `tests/reporting_sarif.rs` | 7 433 | 241 | §6.6 |
| `tests/rules_finding.rs` | 7 257 | 285 | §6.7 |
| `tests/engine_observability.rs` | 6 331 | 206 | §6.8 |
| `tests/app_inline_ignore.rs` | 6 156 | 231 | §6.9 |
| `tests/go_cwe_detector_integration.rs` | 5 452 | 177 | §6.10 |
| `tests/engine_baseline.rs` | 4 889 | 150 | §6.11 |
| `tests/reporting_text.rs` | 4 416 | 163 | §6.12 |
| `tests/lang_go_detectors_cwe_facts.rs` | 4 313 | 150 | §6.13 |
| `tests/fixture_manifest_integration.rs` | 3 267 | 111 | §6.14 |
| `tests/export.rs` | 3 165 | 92 | §6.15 (optional) |
| `tests/lang_go_cwe_metadata.rs` | 3 089 | 105 | §6.16 |
| `tests/perf_regression.rs` | 2 529 | 74 | §6.17 (no split) |
| `benches/incremental_scan.rs` | 6 176 | 154 | §6.18 |
| `benches/scan_throughput.rs` | 2 319 | 76 | §6.19 (no split) |
| `tests/engine_ignore.rs` | 2 290 | 97 | §6.20 |
| `tests/go_perf_detector_integration.rs` | 2 236 | 71 | §6.21 (no split) |
| `tests/ast_walk.rs` | 2 203 | 84 | §6.22 |
| `tests/lang_go_detectors_cwe_common.rs` | 2 135 | 75 | §6.23 |
| `tests/rules_emit.rs` | 2 121 | 85 | §6.24 (no split) |
| `tests/rules_fingerprint.rs` | 2 119 | 81 | §6.25 (no split) |

## Summary

- **Total files over 2 000 chars:** ~95
- **Total files over 3 000 chars:** ~88
- **Total files over 10 000 chars:** 13 (5 are PERF detectors, 4 are engine, 2 are reporting/registry, 1 is tests, 1 is `app.rs`)
- **Largest file:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse.rs` at **106 814 chars / 3 045 lines** with 60 detector functions.

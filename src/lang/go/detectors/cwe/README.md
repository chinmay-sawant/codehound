# Go CWE Detector

This module implements the Go CWE fixture detector as one bundled scan, not as one detector type per CWE.

## Pipeline

1. The engine parses each Go unit once.
2. File collection already honors language filtering, `.codehoundignore`, and config-driven `include`/`exclude` path globs before the Go detector runs.
3. `GoCweScan` builds `GoUnitFacts` once for that `ParsedUnit`.
4. Rule evaluators query those facts plus a few targeted source-shape checks.
5. Matching rules emit `Finding` values directly.

The current implementation keeps the hot path file-local and sequential. The engine already parallelizes across files, so the detector does not add nested intra-file parallelism.

Rule activation is also pre-filtered by the merged `ScanContext`: config `only`/`skip` and CLI `--only`/`--skip` combine additively before the detector is entered.

## Fact Model

`facts.rs` builds reusable per-unit evidence such as:

- normalized call facts
- declarations and literal initializers
- assignment shapes
- request-input origin hints
- guard signals such as path cleaning and prefix checks

Rules should prefer these facts when the pattern is structural. Plain source scans are still acceptable for narrowly fixture-shaped patterns where introducing more indexing would add cost without improving reuse.

## Rule Structure

The detector lives in [mod.rs](/home/chinmay/ChinmayPersonalProjects/codehound/src/lang/go/detectors/cwe/mod.rs) as:

- metadata constants with one structured self-CWE reference per rule
- a typed [registry.toml](/home/chinmay/ChinmayPersonalProjects/codehound/src/lang/go/detectors/cwe/registry.toml) (source of truth for `build.rs`)
- domain modules under [domains/](/home/chinmay/ChinmayPersonalProjects/codehound/src/lang/go/detectors/cwe/domains/) with rule functions such as `detect_cwe_22`
- one `run` orchestrator and a `SourceIndex` built once per file for hot substring guards

This shape keeps registration static and avoids the overhead of a trait-object registry for every CWE.

## Suppression Philosophy

Safe fixtures are handled as evidence-based non-matches or suppressions, not as a second “safe detector” pipeline.

Examples:

- path traversal rules suppress when canonicalization and prefix confinement are present
- SQL-oriented rules suppress when the query stays parameterized
- URL and webhook rules suppress when strict validation evidence is visible

The important constraint is locality: suppression should be cheap, deterministic, and justified by concrete facts in the same unit.

## Adding a Rule

1. Add the rule id to `GO_CWE_RULE_IDS`.
2. Add a `META_CWE_*` entry.
3. Gate it in `GoCweScan::run`.
4. Implement `detect_cwe_*`.
5. Add framework and stdlib fixture coverage in [tests/go_cwe_detector_integration.rs](/home/chinmay/ChinmayPersonalProjects/codehound/tests/go_cwe_detector_integration.rs).
6. Keep [tests/lang_go_cwe_metadata.rs](/home/chinmay/ChinmayPersonalProjects/codehound/tests/lang_go_cwe_metadata.rs) green so fixture inventory, detector registration, and metadata stay aligned.
7. Verify with:
   - `cargo test --test go_cwe_detector_integration`
   - `cargo test --test fixture_manifest_integration`

Do not add inline tests under `src/lang/go/detectors/`.

## When To Use Facts vs Regex-Like Source Checks

Prefer `GoUnitFacts` when:

- the rule depends on reusable structure
- multiple rules need the same origin or guard evidence
- the pattern needs normalized call, assignment, or declaration data

Prefer a targeted source-shape check when:

- the rule is intentionally narrow to one fixture family
- the evidence is textual and not reused elsewhere
- adding a new fact type would cost more complexity than the rule is worth

If several rules start repeating the same source checks, promote that evidence into `GoUnitFacts`.

## Performance Notes

Current verification relies on repository tests:

- `tests/go_cwe_detector_integration.rs`
- `tests/fixture_manifest_integration.rs`
- `tests/perf_regression.rs`

The current design goal is simple:

- one fact-build pass per file
- no repeated full AST walks per rule
- no nested detector parallelism unless profiling proves a need

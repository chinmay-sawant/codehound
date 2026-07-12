# CodeHound — Pull Request Draft

## PR title

`refactor: split Go CWE detector and add PERF planning`

---

## Summary

This PR implements the full Go heuristic rollout for both `tests/fixtures/go/stdlib/` and `tests/fixtures/go/frameworks/`, covering the current 175-rule Go `CWE-*` ruleset with active detections and repository-level verification. It also removes the old Go `SLOP*` path, adds a forward-looking `PERF-*` plan and registry entries for future Go performance rules, and finally refactors the large Go `CWE-*` detector module into smaller files without changing behavior.

---

## Motivation / context

- The branch includes the completed Go heuristic implementation for the current 175-entry Go ruleset and needs to describe that outcome clearly in the PR.
- The existing `src/lang/go/detectors/cwe/mod.rs` had grown to nearly 8,000 lines, which made review and maintenance unnecessarily difficult.
- We also wanted a clean replacement for the removed Go `SLOP*` rule family, but only as planned future work and only for performance cases that are not already covered by the active Go `CWE-*` ruleset.

---

## Changes

### Go heuristic implementation

- Implemented active Go `CWE-*` detections for the full current Go ruleset across both stdlib and framework fixtures.
- Completed repository-level Go coverage for the current 175-rule Go heuristic set.
- Kept Go detector testing in `tests/` rather than inline in detector modules.
- Removed the old Go `SLOP*` runtime detector path so the active Go detector surface is centered on the Go `CWE-*` bundle.

### Go CWE module refactor

- Split the large Go CWE detector module into smaller files while preserving all existing constants, helper functions, rule ids, and detector functions.
- Kept the runtime behavior intact by moving orchestration into a thin `mod.rs` coordinator with a static dispatch table.
- Moved metadata constants into `src/lang/go/detectors/cwe/metadata.rs`.
- Moved shared helper predicates into `src/lang/go/detectors/cwe/common.rs`.
- Split detector implementations across:
  - `src/lang/go/detectors/cwe/detector_group_a.rs`
  - `src/lang/go/detectors/cwe/detector_group_b.rs`
  - `src/lang/go/detectors/cwe/detector_group_c.rs`

### Future Go performance planning

- Added a new Go-only future plan at `plans/v0.0.1/go/perf-heuristics-and-sarif.md`.
- Defined a dedicated `PERF-*` rule family for future Go performance heuristics.
- Explicitly scoped that plan to both `tests/fixtures/go/stdlib/` and `tests/fixtures/go/frameworks/`.
- Documented the non-duplication boundary so future `PERF-*` work does not overlap with the active Go `CWE-*` security rules.
- Added SARIF rollout planning for mixed `CWE-*` and `PERF-*` output.

### Rules registry

- Added planned `PERF-001` through `PERF-016` entries to `ruleset/golang/golang.json`.
- Used stable string ids like `PERF-001` to match the future detector and SARIF rule ids.
- Marked those entries as `Planned` rather than implying active detection.

---

## Code snippets (if applicable)

### Before

```rust
// src/lang/go/detectors/cwe/mod.rs
// One large module containing metadata, orchestration,
// helpers, and all Go CWE detector functions.
```

### After

```rust
// src/lang/go/detectors/cwe/mod.rs
mod common;
mod detector_group_a;
mod detector_group_b;
mod detector_group_c;
mod metadata;

const DETECTORS: &[(&str, DetectorFn)] = &[
    ("CWE-15", detect_cwe_15),
    // ...
];
```

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | No intended runtime regression from the refactor; detector dispatch remains static and fact-building behavior is unchanged. |
| **Memory** | No meaningful change expected. |
| **Behavior / correctness** | The branch adds active coverage for the current 175-rule Go `CWE-*` ruleset and preserves that behavior through the module split. |
| **API / CLI** | No user-facing CLI or API changes. |
| **Dependencies** | None. |
| **Binary size / build time** | No meaningful change expected. |

---

## Breaking changes / migration

None.

---

## Architecture notes

The Go CWE detector is now split by responsibility:

- `metadata.rs` contains rule metadata and the Go CWE rule id list
- `common.rs` contains small shared helper predicates
- `detector_group_*.rs` contain the rule implementations
- `mod.rs` owns detector registration and dispatch

This preserves the bundled-scan model while making the codebase easier to review and extend.

At a higher level, the branch leaves Go with:

- one active bundled Go `CWE-*` detector path
- repository-level tests for the implemented Go heuristics
- a separate planned `PERF-*` family for future performance rules instead of reviving the old `SLOP*` path

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/*.rs` | Implements and now modularizes the active Go `CWE-*` detector bundle |
| `tests/go_cwe_detector_integration.rs` | Repository-level coverage for the implemented Go `CWE-*` rules |
| `tests/fixture_manifest_integration.rs` | Manifest-backed verification for Go fixture expectations |
| `src/lang/go/detectors/cwe/mod.rs` | Replaced monolith with coordinator/dispatch module |
| `src/lang/go/detectors/cwe/metadata.rs` | Extracted Go CWE metadata constants and rule id list |
| `src/lang/go/detectors/cwe/common.rs` | Extracted shared helper functions |
| `src/lang/go/detectors/cwe/detector_group_a.rs` | Extracted first detector batch |
| `src/lang/go/detectors/cwe/detector_group_b.rs` | Extracted second detector batch |
| `src/lang/go/detectors/cwe/detector_group_c.rs` | Extracted third detector batch |
| `plans/v0.0.1/go/perf-heuristics-and-sarif.md` | Added future Go `PERF-*` and SARIF plan |
| `ruleset/golang/golang.json` | Added planned `PERF-001` through `PERF-016` registry entries |

---

## Test plan

- [x] `cargo test --test go_cwe_detector_integration --quiet`
- [x] `cargo test --test fixture_manifest_integration --quiet`
- [x] `make lint`
- [x] `make fmt`

### Commands

```sh
cargo test --test go_cwe_detector_integration --quiet
cargo test --test fixture_manifest_integration --quiet
make lint
make fmt
```

---

## Screenshots / sample output

```text
running 350 tests
...
test result: ok. 350 passed; 0 failed
```

```text
fixture_manifest_integration: passed
```

---

## Related issues

- None linked

---

## Follow-ups (out of scope)

- Implement the planned `PERF-*` Go performance detector family.
- Add `PERF-*` fixtures and repository-level integration tests.
- Extend SARIF metadata once `PERF-*` runtime detection exists.

---

## Reviewer checklist

- [x] Behavior matches summary and test plan (Go CWE split into domains/ + taint/, PERF detectors live, typed registry.toml)
- [~] No unrelated changes in diff (needs review — PR diff check) (deferred → see plans/v0.0.3/)
- [x] New planning docs match the current Go ruleset scope (perf-heuristics-and-sarif.md exists, PERF detectors implemented)
- [x] Go `CWE-*` detector behavior is unchanged after the split (GoCweScan dispatch via mod.rs + include! from build.rs gen)
- [~] No secrets or generated artifacts committed (needs review — security check) (deferred → see plans/v0.0.3/)

---

## Release notes (if user-facing)

Implement the current 175-rule Go `CWE-*` heuristic set, refactor the Go detector into smaller modules, and add planned `PERF-*` Go performance rule definitions for future work.

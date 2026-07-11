# Rule RFC template

Use this when proposing a new PERF / BP / CWE detector.

## Metadata

| Field | Value |
|-------|-------|
| Proposed ID | PERF-NNN / BP-NN / CWE-NNN |
| Pack | recommended / perf / security / style / none |
| Severity | info / low / medium / high |
| Maturity | taint-core / structural / heuristic / fixture-only / reserved |

## Threat / value model

Why does this rule pay for itself in real services?

## Overlap

| Tool | Overlap? | Action if weaker |
|------|----------|------------------|
| go vet | | default-off / delete / keep unique |
| staticcheck | | |
| errcheck / revive | | |
| govulncheck | | |

## Detection sketch

- AST / facts / needles / taint?
- Precision risks (FP examples)
- FN examples

## Fixtures

- [ ] vulnerable + safe `.txt` fixtures
- [ ] framework variant if applicable
- [ ] exclusive-fire / line / evidence oracle for taint-core

## Detection notes quality

`detection_notes` in ruleset JSON must match the implementation (no vague
“taint analysis…” unless the detector actually uses taint).

## Rollout

- Default pack membership
- Baseline / ignore guidance

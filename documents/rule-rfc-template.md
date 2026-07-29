# Rule RFC template

Use this when proposing a new PERF / BP / CWE detector. Step 1 in
`CONTRIBUTING.md`. Catalog hub: [rule-catalog.md](./rule-catalog.md).

## Metadata

| Field | Value |
|-------|-------|
| Proposed ID | `PERF-NNN` / `BP-NN` / `CWE-NNN` (unpadded) |
| Pack impact | recommended / perf / security / style / none / all-only |
| PERF tier (if PERF) | S / A / B / C / unclassified |
| Severity | info / low / medium / high / critical |
| Maturity | taint-core / structural / heuristic / fixture-only / reserved |
| Owner | |
| Issue / PR | |

## Threat / value model

Why does this rule pay for itself in real services? Who fixes it?

## Overlap

| Tool | Overlap? | Action if weaker |
|------|----------|------------------|
| go vet | | default-off / delete / keep unique |
| staticcheck / gocritic / prealloc | | |
| errcheck / revive | | |
| govulncheck | | |
| Existing CodeHound PERF/BP/CWE | twin IDs? | |

## Detection sketch

- AST / facts / needles / taint / project-level?
- Precision risks (FP examples)
- FN examples
- Evidence type(s) (`DangerousCall`, `TaintFlow`, …)

## Implementation map (fill when implementing)

| Piece | Path / notes |
|-------|----------------|
| Ruleset JSON | `ruleset/golang/…` |
| Registry TOML | e.g. `src/lang/go/detectors/perf/registry/…` (`[[detector]]`) |
| Detector fn | |
| Tier / pack update | `tiers.rs` / `pack.rs` / profile tests |
| Fixtures | |

## Fixtures

- [ ] vulnerable + safe fixtures (canonical naming; zero-pad only where corpus already does)
- [ ] framework variant if applicable
- [ ] exclusive-fire / line / evidence oracle for taint-core
- [ ] real-world multi-file fixture when S-tier

## Detection notes quality

`detection_notes` in ruleset JSON must match the implementation (no vague
“taint analysis…” unless the detector actually uses taint).

## Acceptance criteria (definition of done)

- [ ] Unit / integration tests green
- [ ] `codehound --explain <ID>` shows correct pack + maturity
- [ ] Pack docs updated if membership changes (`go-recommended-pack.md`,
      `perf-tiers.md`, `bad-practices.md` as needed)
- [ ] No false claim of full catalog completeness in partial markdown notes
- [ ] Module size / clippy / fmt gates pass

## Rollout

- Default pack membership (or `--profile all` only)
- Quarantine until structural bar (`fixture-only` / `reserved`)
- Baseline / ignore guidance for brownfield
- Canary / perf impact notes if on hot path

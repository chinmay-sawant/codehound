# chore: integrate epic #136 Phase 5 G1–G6 workstreams

## Summary

Single integration of Phase 5 backlog epic #136: gate evidence evaluations for G1/G2/G4/G5/G6 (remain deferred), plus G3 product change quarantining injection resource CWE-619/917 as fixture-only. Closes #136–#142.

---

## Child streams

| Issue | Stream | Branch | PR | Outcome |
|------:|--------|--------|-----|---------|
| #137 | G1 BP expansion | `chore/phase5-g1-bp-expansion` | #147 | **Keep deferred** — BP-71 canary 0 actionable |
| #138 | G2 CWE-277 Structural | `chore/phase5-g2-cwe-277` | #149 | **Keep Heuristic** — 0/376 canary |
| #139 | G3 FO residual | `chore/phase5-g3-fo-generalization` | #148 | **CWE-619/917 → fixture-only** |
| #140 | G4 typed Go | `docs/phase5-g4-typed-go-gate` | #145 | **Remain deferred** — Gate A fails |
| #141 | G5 advanced taint | `docs/phase5-g5-taint-ceilings` | #146 | **Remain deferred** + silence test |
| #142 | G6 Python | `docs/phase5-g6-python-gate` | #144 | **Remain deferred** — Gate B fails |

---

## Changes

### Product (G3 only)
- `maturity.rs`: FO for CWE-619, CWE-917 + tests
- `injection/resource.rs` freeze; NEEDLES labels; audit §2.16

### Gate evidence (G1/G2/G4/G5/G6)
- `phase5-g1-bp-reopen-evidence.md`
- `phase5-g2-cwe-277-reopen-evidence.md`
- `phase5-g4-typed-go-gate-eval.md`
- `phase5-g5-taint-ceiling-eval.md` + channel handoff silence test
- `phase5-g6-python-gate-eval.md`

### Explicit non-ships
- No bulk BP rules, no CWE-277 Structural, no go/packages, no channel taint edges, no Python multi-rule catalog

---

## Test plan

- [x] Merge children
- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures`
- [x] Focused tests green; `make test` recommended before land

---

## Related issues

- Closes #137
- Closes #138
- Closes #139
- Closes #140
- Closes #141
- Closes #142
- Closes #136

---

## PR metadata

- [x] Assignee @me
- [x] Labels documentation + enhancement

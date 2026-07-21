# docs(phase5): G5 advanced taint ceiling evaluation (remain deferred)

## Summary

Docs-only G5 evaluation under epic #136 / issue #141: pick **one** advanced
taint ceiling (**channel / goroutine handoffs**), record the shipped FN model,
write the FP/FN contract required to reopen, and **remain deferred**. Optional
unit test documents that a classic send→receive→sink pattern stays silent (no
invented channel edges). **Closes #141 · Relates to #136.**

---

## Motivation / context

- Gate: [`phase5-gated-work.md`](./phase5-gated-work.md) G5  
- Prior decision: [`taint-capability-decision.md`](./taint-capability-decision.md) §4  
- Product honesty: [`documents/taint.md`](../../documents/taint.md), ADR 0003  
- Backlog map: [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md)  
- Branch: `docs/phase5-g5-taint-ceilings`  
- Base: `origin/master` @ `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`

Issue #141 requires a **specific** enhancement with a written FP/FN contract
before implementation. This PR is the evaluation tranche: **no fake dataflow**,
no whole-program claim, no external-package or decoder-receiver edges.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-g5-taint-ceiling-eval.md` | Chosen ceiling, current contract, FP/FN reopen rules, remain-deferred decision |
| `plans/v0.0.5/pr-phase5-g5-taint.md` | This PR body |
| `src/lang/go/detectors/cwe/taint/graph_query/tests.rs` | Optional: `channel_send_receive_handoff_remains_silent_fn` documents honest FN |

### Decision snapshot

| Item | Outcome |
|------|---------|
| **Chosen ceiling** | Channel / goroutine handoffs |
| **Not evaluated here** | External-package summaries; decoder receivers (still deferred per prior decision) |
| **Implementation** | **Remain deferred** |
| **Reopen** | Written concurrent DF contract + fixtures + canary + new scoped issue (see eval doc) |

---

## Out of scope (explicit)

- Channel/goroutine assignment or transfer edges in the engine
- External-package taint summaries / import-path wiring
- `(*Decoder).Decode` / decoder-receiver output bridges
- Typed Go / `go/packages` / G4 (#140)
- Expanding residual IP-010 source-on-send attribution
- Whole-program or security-grade concurrent taint claims
- Changes to README marketing copy beyond existing honesty

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | None (test asserts existing silence only) |
| **API / CLI** | None |
| **Taint graph** | Unchanged — no new edges |
| **Packs / maturity** | Unchanged |

---

## Test plan

- [x] Eval doc names one ceiling and reopen FP/FN contract
- [x] Cross-links to #141, #136, gate ledger, taint decision, ADR 0003
- [x] Unit test: channel send recorded unsupported; send→receive→sink finds **no** path
- [ ] `cargo test --lib channel_send_receive_handoff_remains_silent_fn` (or module path) on author machine / CI
- [ ] Reviewer confirms no invented dataflow and “remain deferred” is unambiguous

---

## Checklist

- [x] Closes #141 (G5 ceiling evaluation: remain deferred + reopen contract)
- [x] Relates to #136 (Phase 5 implementation backlog epic)
- [x] Label: `documentation`
- [x] Assignee: @me
- [x] Commit message: `docs(phase5): G5 advanced taint ceiling evaluation (remain deferred)`

---

## Related issues

- Closes #141
- Relates to #136

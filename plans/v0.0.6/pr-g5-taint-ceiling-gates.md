# chore(gates): G5 channel taint ceiling contract (keep edges deferred)

## Summary

- Pick **one** G5 ceiling: **channel / goroutine handoffs** (siblings stay deferred).
- Lock the FP/FN capability contract and a transfer-record design sketch that
  **forbids** fake assignment edges.
- Verify honesty unit tests still pass after G4 typed landing.
- **No engine channel edges** in this PR — implementation is a separate tranche.

---

## Motivation / context

Gated stream [#156](https://github.com/chinmay-sawant/codehound/issues/156) under epic [#151](https://github.com/chinmay-sawant/codehound/issues/151).

Prior Phase 5 eval: [`../v0.0.5/phase5-g5-taint-ceiling-eval.md`](../v0.0.5/phase5-g5-taint-ceiling-eval.md).  
G4 product typed layer is on `master`; this package records that types **do not**
authorize concurrent handoffs.

---

## Changes

| Path | Change |
|------|--------|
| `plans/v0.0.6/g5-channel-capability-contract.md` | Locked FP/FN + TP bar + G4 independence |
| `plans/v0.0.6/g5-channel-design-sketch.md` | Transfer records; pairing rules; IP-010 plan |
| `plans/v0.0.6/evidence-g5-taint-ceiling.md` | Gate results + test evidence |
| `plans/v0.0.6/gated-g5-advanced-taint.md` | Checklist progress |
| `plans/v0.0.6/pending-work.md` | Ledger note |

---

## Test plan

- [x] `cargo test --locked --lib channel_send` — 2 passed
- [x] Docs-only; no detector/engine edits

---

## Related issues

Relates to #156 · Relates to #151  
(Does **not** close #156 — impl tranche still open.)

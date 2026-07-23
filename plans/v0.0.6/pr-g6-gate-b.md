# docs(gates): refresh G6 Python Gate B evaluation

## Summary

- Re-score Gate **B1–B4** for multi-rule Python on current `master` (`35b27ec`).
- **All reopen gates still unmet** — remain deferred (SLOP101 / ADR 0005 Go-first demote).
- Docs-only: evidence + checklist refresh; **no** Python detectors, **no** Cargo default flip, **no** marketing claim expansion.

---

## Motivation / context

Gated stream [#157](https://github.com/chinmay-sawant/codehound/issues/157) under epic [#151](https://github.com/chinmay-sawant/codehound/issues/151).

Prior Phase 5 eval: [`../v0.0.5/phase5-g6-python-gate-eval.md`](../v0.0.5/phase5-g6-python-gate-eval.md) (remain deferred).  
This refresh confirms the same decision after Class B / G4 / G5 progress on Go — none of which funds or reverses the Python demote.

---

## Results

| Gate | Result | Notes |
|------|--------|-------|
| **B1** Funding / demand | **FAIL** | #157 is gated backlog, not funded invest; no owner/metrics |
| **B2** Invest/reverse ADR Accepted | **FAIL** | ADR 0005 still Accepted demote; no 0006+ invest ADR |
| **B3** Honesty bar (invest) | **N/A** | Demote honesty OK; invest claims blocked on B1–B2 |
| **B4** Engineering floor | **FAIL** | SLOP101 only; synthetic fixtures; no real-module canary |
| **Overall** | **Remain deferred** | Do not reopen multi-rule Python catalog |

Evidence: [`evidence-g6-gate-b.md`](./evidence-g6-gate-b.md)

---

## Changes

| Path | Change |
|------|--------|
| `plans/v0.0.6/evidence-g6-gate-b.md` | B1–B4 re-score + inventory on `35b27ec` |
| `plans/v0.0.6/gated-g6-python-catalog.md` | Checklist statuses + evidence link |
| `plans/v0.0.6/pending-work.md` | G6 ledger line refreshed |
| `plans/v0.0.6/pr-g6-gate-b.md` | This PR body |

**Skipped:** `draft-adr-python-invest.md` — not useful without B1 funded demand (would invert gate order).

---

## Explicit non-actions

- No new Python detectors or rules  
- No Cargo `default` / `python` feature flip  
- No ADR 0005 body edit; no Accepted invest ADR  
- No marketing claim expansion  

---

## Test plan

- [x] Docs-only; inventory cross-checked against `src/lang/python/`, `Cargo.toml`, README, ROADMAP, ADR list  
- [ ] Optional: `make lint` (docs only)

---

## Related issues

Relates to #157 · Relates to #151  

Does **not** close #157 — Gate B still FAIL; implementation remains blocked until B1 + Accepted invest/reverse ADR.

# docs(gates): G4 Gate A A1–A6 package (typed Go)

## Summary

- Complete **Gate A** for optional typed Go (`go/packages`) under G4 / #155.
- Record A1–A6 evidence, FN/FP contract, accepted architecture, and external cost probe.
- **No** product `--typed` flag, Cargo bridge, or detector rewrites in this PR.

---

## Motivation / context

Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151) · Issue [#155](https://github.com/chinmay-sawant/codehound/issues/155).

Prior eval (remain deferred): [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md).  
Gate source: [`../v0.0.5/roadmap-gates-49.md`](../v0.0.5/roadmap-gates-49.md) Gate A.

Catalog residuals (R1–R8) + G3 FO + P1 pilot unlocked A1/A2 honesty/PERF bars that failed on 2026-07-22.

**Branch:** `chore/g4-gate-a-package`  
**Base:** `origin/master` @ post-#180

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.6/evidence-g4-gate-a.md` | A1–A6 evidence + cost table |
| `plans/v0.0.6/g4-typed-capability-contract.md` | A3 FN/FP contract |
| `plans/v0.0.6/g4-typed-architecture.md` | A4 accepted architecture |
| `plans/v0.0.6/gated-g4-typed-go.md` | Checklist Gate A all `[x]` |
| `plans/v0.0.6/pending-work.md` | Ledger |
| `plans/v0.0.5/roadmap-gates-49.md` | Met? → Yes |
| `plans/v0.0.5/phase5-g4-typed-go-gate-eval.md` | Supersede note |

---

## Gate A outcome

| # | Result |
|---|--------|
| A1 PERF sign-off | **PASS** (95% actionable + P1 stable + stop-the-line clear) |
| A2 Honesty ledger | **PASS** (FO/Heuristic/gated map; typed ≠ paper holes) |
| A3 Capability contract | **PASS** |
| A4 Architecture | **PASS** |
| A5 Cost | **PASS** (opt-in only; ~100–400× wall vs TS; RSS up to ~1GB gorl) |
| A6 Non-blocker | **PASS** |

---

## Cost probe (A5) — external only

Throwaway `packages.Load` (not in CodeHound binary):

| Target | TS recommended wall | Load wall | Load RSS max |
|--------|--------------------:|----------:|-------------:|
| go-retry | 0.03s | 14.9s | 221 MB |
| monsoon | 0.16s | 25.6s | 306 MB |
| gorl | 0.09s | 38.9s | **1074 MB** |
| gopdfsuit | ~0.5–0.9s class | 43.9s | 218 MB |

---

## Test plan

| Check | Result |
|-------|--------|
| Docs-only PR | n/a code |
| `make lint` / `make test` | optional smoke if CI requires — no src change |

---

## Impact

| Surface | Change |
|---------|--------|
| Product binary | **None** |
| Recommended pack | **None** |
| #155 | Gate A complete; **implementation still open** |

---

## Related issues

Relates to #155  
Relates to #151  
Relates to #49  

Does **not** close #155 (impl remaining).

---

## Explicit non-goals

- No `--typed` shipping
- No `go/packages` in Cargo/CodeHound
- No G5 taint work

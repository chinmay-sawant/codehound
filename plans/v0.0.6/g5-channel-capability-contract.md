# G5 — Channel / goroutine capability contract (v0.0.6)

> **Issue:** [#156](https://github.com/chinmay-sawant/codehound/issues/156) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Ceiling chosen:** Channel / goroutine concurrent handoffs  
> **Adopts:** [`../v0.0.5/phase5-g5-taint-ceiling-eval.md`](../v0.0.5/phase5-g5-taint-ceiling-eval.md) FP/FN section  
> **Date:** 2026-07-23  
> **Status:** Contract locked for reopen; **product channel edges not shipped**

---

## Scope of this contract

This contract applies only to **channel send/receive** and **goroutine spawn** as
taint transfer. It does **not** authorize:

- External-package summaries  
- Decoder-receiver output expansion  
- Whole-program / security-grade concurrent taint  
- Treating G4 `--typed` / `go list` facts as channel support  

Sibling ceilings stay deferred until separately contracted.

---

## Shipped behavior (must remain true until an impl PR)

| Site | Behavior |
|------|----------|
| `ch <- x` | `UnsupportedFlowKind::Channel` — **not** an assignment edge |
| `y := <-ch` | No designed transfer from send sites |
| `go f(...)` | `UnsupportedFlowKind::Goroutine` — spawn ≠ taint handoff |
| Classic send→receive→sink | **Honest FN** (silence unit tests) |

Product docs: [`documents/taint.md`](../../documents/taint.md) Limitations — Channel/goroutine.  
ADR: [0003](../../documents/adr/0003-taint-model.md) — prefer honest FN over pretend channels.

---

## False negatives (allowed)

| Case | Expected |
|------|----------|
| Multi-sender / multi-receiver without alias model | May FN |
| `select` / default / timeout races | May FN until modeled |
| Buffer / close / range-over-channel lifecycle | May FN |
| Cross-goroutine heap share without channel | Out of scope unless separately contracted |
| Opaque callees inside `go` bodies | Same opacity as today |
| Security-grade whole-program concurrent taint | **Never claimed** in 0.1.x |

---

## False positives (must not ship)

| Anti-pattern | Forbidden |
|--------------|-----------|
| Every `ch <- x` as `ch = x` assignment | Invents flows |
| Every `y := <-ch` as “last send” without pairing rules | Invents order |
| All senders → all receivers in a package | Mass FP |
| Growing IP-010 source-on-send quirk as “channel support” | Non-contractual |
| Docs claiming channel support with only AST sugar | Violates ADR 0003 |

---

## True positives (minimum bar if an impl PR reopens)

1. Same-function **unbuffered** single-sender / single-receiver handoff with proven channel binding.  
2. Safe constant / sanitized send → receive→sink must **not** fire.  
3. Unrelated `ch2` must not inherit taint from `ch1`.  

Stretch (select, buffer, multi-goroutine) only if claimed in docs with matching fixtures.

---

## Dependency clarity vs G4

G4 optional typed facts (`--typed` / `go list`) may later help **type** channel
element types. They **do not** authorize send/receive transfer edges by themselves.
A G5 impl PR must not smuggle channel modeling under a typed-Go ticket (or vice versa).

---

## Reopen → implementation handoff

Reopen gates for this **evaluation / contract package** are satisfied by the
docs + honesty tests in the G5 gates PR.

**Engine implementation** requires a **separate scoped PR/issue** that ships:

- Transfer-record design (see [`g5-channel-design-sketch.md`](./g5-channel-design-sketch.md))  
- Vuln + safe + multi-channel negative fixtures  
- Unit + integration tests  
- Canary sanity (no mass FP)  
- Same-PR `documents/taint.md` honesty update  
- Explicit IP-010 residual replace or quarantine plan  

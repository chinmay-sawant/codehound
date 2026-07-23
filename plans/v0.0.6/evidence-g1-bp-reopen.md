# v0.0.6 — G1 BP-71 reopen evidence (refresh)

> **Issue:** [#152](https://github.com/chinmay-sawant/codehound/issues/152) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Checklist:** [`gated-g1-bp-expansion.md`](./gated-g1-bp-expansion.md)  
> **Prior:** [`../v0.0.5/phase5-g1-bp-reopen-evidence.md`](../v0.0.5/phase5-g1-bp-reopen-evidence.md)  
> **Date:** 2026-07-23  
> **CodeHound:** `4b3ec9b` (`origin/master` post P1 #178)  
> **Outcome:** **Keep deferred — no BP-71 detector** (0 actionable correctness hits)

---

## Reopen gates (this refresh)

| Gate | Result |
|------|--------|
| Non-idiomatic multi-return discard on pinned real modules | **FAIL** — allowlist shapes present but all **idiomatic** |
| Overlap vs BP/CWE/staticcheck/noctx | Unchanged vs Phase 5 G1 (Write/Copy/`_, err` are normal Go) |
| Vulnerable + safe fixtures | **Blocked** — no pattern worth encoding |
| Release canary + FP budget | **Blocked** — no detector |
| Scope one BP family (BP-71) | Still the only `defer-needs-canary` candidate; **not proven** |

**Decision:** do **not** implement BP-71 or bulk BP-66+. Explicit non-goals remain.

---

## Method

BP-71 is **not implemented** — no `--only BP-71`. Evidence is ripgrep static sampling on non-test `.go` (same patterns as Phase 5 G1) on the five pinned trees.

### Allowlist-shaped primary discard counts (non-test, 2026-07-23)

| Callee class | gopdfsuit | monsoon | go-retry | gorl | no-mistakes | Reading |
|--------------|----------:|--------:|---------:|-----:|------------:|---------|
| `io.Copy` `_` primary | 10 | 0 | 0 | 0 | 4 | Idiomatic — err is the contract |
| `Write` / `WriteString` `_` primary | 14 | 2 | 0 | 0 | 13 | Textbook `if _, err := w.Write` |
| `fmt.Sscanf` / Fscan `_` primary | 11 | 0 | 0 | 0 | 0 | Single-verb / err-gated parses |

**Actionable correctness hits (reviewed):** **0**

Same qualitative conclusion as [`phase5-g1-bp-reopen-evidence.md`](../v0.0.5/phase5-g1-bp-reopen-evidence.md): a naive BP-71 on this allowlist would mass-FP.

---

## What would reopen implementation

1. A **non-Write / non-Copy** (or otherwise non-idiomatic) multi-return discard class with reviewed real-module correctness bugs.  
2. Overlap analysis + fixtures with near-miss negatives.  
3. Agreed FP budget on the pin set.  
4. Then ship **one** scoped BP family only.

Until then: leave #152 deferred; no new BP rules.

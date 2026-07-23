# v0.0.6 — G2 CWE-277 Structural reopen evidence (refresh)

> **Issue:** [#153](https://github.com/chinmay-sawant/codehound/issues/153) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Checklist:** [`gated-g2-cwe-277-structural.md`](./gated-g2-cwe-277-structural.md)  
> **Prior:** [`../v0.0.5/phase5-g2-cwe-277-reopen-evidence.md`](../v0.0.5/phase5-g2-cwe-277-reopen-evidence.md)  
> **Date:** 2026-07-23  
> **CodeHound:** `4b3ec9b` (`origin/master` post P1 #178)  
> **Outcome:** **Keep Heuristic — reopen gates fail** (still 0 real-module hits)

---

## Reopen gates (this refresh)

| Gate | Result |
|------|--------|
| Reviewed actionable real-module hit for CWE-277 | **FAIL** — 0/376 release canary |
| Mode-variant / scope negatives | N/A until a hit exists; corpus MkdirAll sites use `0755` / `0o755`, not world-writable |
| Audit §1.3 bar fully met | **FAIL** — no promotion evidence |
| Maturity + profile + tests in same change | **Not started** (blocked) |

**Decision:** do **not** Structural-promote. Do **not** invent mode widening without a hit.

---

## Canary (release binary)

```sh
target/release/codehound <target> --profile all --only CWE-277 \
  --format json --json-envelope --no-fail --no-cache
```

| Repository | Files | Findings |
|------------|------:|---------:|
| gopdfsuit | 78 | 0 |
| monsoon | 43 | 0 |
| go-retry | 5 | 0 |
| gorl | 28 | 0 |
| no-mistakes | 222 | 0 |
| **Total** | **376** | **0** |

Identical outcome to Phase 5 G2 (2026-07-22).

### Static context (non-finding)

Pinned trees show `os.MkdirAll(..., 0755|0o755)` and one `syscall.Umask(0o077)` (no-mistakes IPC) — **not** the detector’s `Umask(0)` + `MkdirAll(..., 0777)` co-presence. No `0777` / `0o777` MkdirAll on non-test paths in this pin set.

---

## What would reopen implementation

1. At least one **reviewed actionable** hit on a real module (or expanded pin) for the current or oracle-safe widened shape.  
2. Negatives for safe modes / umask.  
3. Single PR: maturity Structural + profile + tests + re-canary.

Until then: leave #153 deferred; maturity stays Heuristic.

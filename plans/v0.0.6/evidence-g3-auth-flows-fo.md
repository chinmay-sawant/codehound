# Evidence — G3 residual FO: auth_flows deferred siblings

> **Issue:** #154 · **Epic:** #151  
> **Branch:** `chore/g3-auth-flows-fo-residual`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/access_control/auth_and_validation/auth_flows.rs`  
> **Selected family:** R3-deferred auth_flows remainder — **CWE-305–309, 620, 836**  
> **Date:** 2026-07-23

---

## Family inventory and selection

| Rule | Theme | Selected? |
|------|-------|-----------|
| CWE-289 / 290 | Login identity | Done R3 → FO |
| **CWE-305** | Debug flag before subject check | **Yes** |
| **CWE-306** | Destructive action without auth gate | **Yes** |
| **CWE-307** | Login without throttling/lockout | **Yes** |
| **CWE-308** | High-value action without MFA | **Yes** |
| **CWE-309** | Enterprise login without WebAuthn | **Yes** |
| **CWE-620** | Password change without current password | **Yes** |
| **CWE-836** | Password hash accepted as credential | **Yes** |

### Why this family (G3 residual FO path)

1. Explicit R3 deferral — natural next FO residual after 289/290.
2. Cohesive seam file; full fixture oracle (stdlib + frameworks).
3. All seven are SI museum shapes (exact SQL/form/helper co-signals).
4. Prior G3 deferred siblings (260/455, 201/213) already dispositioned via R1/R2.
5. R8 kept 619/917 FO — true generalization still out of scope.

---

## Freeze inventory

| Rule | Primary signals (frozen) | Negatives |
|------|--------------------------|-----------|
| **305** | SI `Query("debug")=="1"` / `Query().Get("debug")=="1"` + `jwt_sub` / `X-JWT-Sub` | (none beyond missing co-signals) |
| **306** | SI `TRUNCATE ledger` without `operator_id` / `X-Operator-ID` | operator gate markers |
| **307** | SI login email lookup without `loginAttempts` / `LoadOrStore` / fixed Sleep | attempt-tracking markers |
| **308** | SI password form + `INSERT INTO wires` without totp / `X-TOTP-Valid` | MFA markers |
| **309** | SI `func EnterpriseLogin` + session shape + username/password forms | webauthn markers |
| **620** | SI `ChangePassword` + `"new_password"` + password UPDATE | `ForgotPassword` / current_password / compare helpers |
| **836** | SI `PasswordHash` / `json:"password_hash"` + hash equality SQL | CompareHashAndPassword / ConstantTimeCompare |

No emit-path / span / needle *value* changes — comments + maturity + NEEDLES labels only.

---

## Call-facts primary analysis

| Rule | Complete call_facts primary? | Decision |
|------|------------------------------|----------|
| 305–309, 620, 836 | **No** | SI museums; order/policy/org markers required → **fixture-only** |

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| 305–309 | **fixture-only** | Exact debug/SQL/form/helper museums; unit-local policy |
| 620 | **fixture-only** | ChangePassword museum; partitions from CWE-640 via ForgotPassword negative |
| 836 | **fixture-only** | Client-supplied hash field museum |

**No Structural.** **No Heuristic keep.** True generalization deferred (G3 hard path).

---

## Canary (worker) — 2026-07-23

```sh
ONLY=CWE-305,CWE-306,CWE-307,CWE-308,CWE-309,CWE-620,CWE-836
# --profile all --only $ONLY
```

| Repo | Files | Findings |
|------|------:|---------:|
| monsoon | 43 | 0 |
| go-retry | 5 | 0 |
| gorl | 28 | 0 |
| no-mistakes | 222 | 0 |
| gopdfsuit | 78 | 0 |
| **Total** | **376** | **0** |

Zero useful hits ⇒ fixture-only quarantine consistent with prior museum families.

---

## Overlap

| Neighbor | Relation |
|----------|----------|
| CWE-640 (FO R6) | Recovery vs 620 change — ForgotPassword partitions |
| CWE-289/290 (FO R3) | Same file; already quarantined |
| CWE-603/613 (FO) | Cookies/header policy neighbors |

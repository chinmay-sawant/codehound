# chore(cwe): G3 FO residual — auth_flows deferred siblings

## Summary

- Close the **G3 residual FO** path for R3-deferred `auth_flows` rules (**CWE-305–309, 620, 836**).
- Freeze SI museum signals (comments only), quarantine maturity to **fixture-only**, label NEEDLES, canary **0/376**.
- True generalization (§1.3) remains deferred — no Structural / Heuristic keep.

---

## Motivation / context

Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151) · Issue [#154](https://github.com/chinmay-sawant/codehound/issues/154).

Plan: [`gated-g3-fo-generalization.md`](./gated-g3-fo-generalization.md)  
Evidence: [`evidence-g3-auth-flows-fo.md`](./evidence-g3-auth-flows-fo.md)

R3 (#160) FO-quarantined CWE-289/290 only and deferred bruteforce/MFA + password siblings. Class B R1/R2 already covered G3’s earlier deferred siblings (260/455 FO; 201/213 Heuristic keep). R8 kept 619/917 FO.

This PR is the sequential next FO residual family under G3 (worktree-deleation single-stream shortcut).

**Base:** `origin/master` @ `bd10c94`  
**Branch:** `chore/g3-auth-flows-fo-residual`

---

## Selection

| Subfamily | Rules | Disposition |
|-----------|-------|-------------|
| Bruteforce / MFA gaps | 305–309 | **fixture-only** |
| Password credential flows | 620, 836 | **fixture-only** |

---

## Changes

### Code
- `auth_flows.rs` — freeze comments for 305–309, 620, 836 (no emit-path change)
- `maturity.rs` — FO + unit tests for all seven
- `source_index.rs` — fixture-literal / negative-gate labels on primary needles

### Plans
- `gated-g3-fo-generalization.md`, `pending-work.md`, `residual-auth-flows.md`
- `evidence-g3-auth-flows-fo.md`, this PR body

---

## Disposition table

| Rule | Disposition | Primary class |
|------|-------------|---------------|
| CWE-305 | fixture-only | debug query + jwt_sub museum |
| CWE-306 | fixture-only | TRUNCATE ledger museum |
| CWE-307 | fixture-only | login lookup without throttle museum |
| CWE-308 | fixture-only | password + wires INSERT without TOTP |
| CWE-309 | fixture-only | EnterpriseLogin password without WebAuthn |
| CWE-620 | fixture-only | ChangePassword without current password |
| CWE-836 | fixture-only | client password_hash as credential |

---

## Test plan

| Check | Result |
|-------|--------|
| `make lint` | pass |
| `cargo test --lib fixture_only_quarantined` | pass |
| `cargo test --test go_cwe_detector_fixtures` | pass (4/4) |
| `make test` | **459/459** passed |
| Canary `--only` seven rules on pinned corpus | **0/376** findings |

---

## Impact

| Surface | Change |
|---------|--------|
| Recommended / security packs | Unchanged (already not on explicit allow-lists; FO excludes Heuristic pack path) |
| `--profile all` / `--only` | Still available for museum rules |
| True generalization | Still deferred (G3 hard path) |

---

## Related issues

Closes #154  
Relates to #151  
Relates to #160 (R3 deferred siblings)

---

## Explicit non-goals

- No bulk FO → Structural catalog flip
- No true generalization of 619/917 or these seven
- No emit-path rewrites

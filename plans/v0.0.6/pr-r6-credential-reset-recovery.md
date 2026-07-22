# chore(cwe): audit credential reset/recovery trust (R6)

## Summary

- Inventory `credential_lifecycle/reset_recovery.rs`; **select** the whole bounded family
  (**CWE-549**, **CWE-640** — file is ~67 lines).
- Freeze primary signals, negatives, fixtures, and maturity state for both rules.
- Document overlap vs OAuth / password-change neighbors (**CWE-620**, **CWE-940**,
  **CWE-941**, **CWE-201**): no ownership collision.
- Propose **fixture-only** dispositions (integrator applies `maturity.rs` / SourceIndex
  NEEDLES labels).
- Oracle-safe detector comments only (no emit-path changes); run focused fixtures +
  two-rule real-module canary.

---

## Motivation / context

Residual catalog slice **R6** of issue
[#163](https://github.com/chinmay-sawant/codehound/issues/163). Relates to epic
[#151](https://github.com/chinmay-sawant/codehound/issues/151).

Phase 2 B1 (#107) dispositioned sibling `credentials_in_source.rs`; `reset_recovery.rs`
was explicitly deferred. This worker completes that deferred family under the v0.0.6
residual program.

**Integration base SHA:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
**Branch:** `chore/cwe-trust-credential-reset`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](../v0.0.5/cwe-catalog-trust-audit.md) §1.3  
**Worker contract:** [`parallel-catalog-program.md`](../v0.0.5/parallel-catalog-program.md) §0.2

---

## Selection inventory

### Owner seam — `credential_lifecycle/`

| Leaf | Rules | Lines (approx) | Fixture coverage |
|------|-------|----------------|------------------|
| `credentials_in_source.rs` | CWE-523, 547, 798 | ~95 | stdlib + frameworks each (B1 done) |
| `key_expiration.rs` | CWE-324 | ~41 | stdlib + frameworks each (R5 — out of scope) |
| `password_aging.rs` | CWE-262, 263 | ~53 | stdlib + frameworks each (R5 — out of scope) |
| **`reset_recovery.rs`** | **CWE-549, 640** | **~67** | **stdlib + frameworks each** |

### Why select both `reset_recovery.rs` rules

1. **File is small enough** — two rules with full oracle pairs; no boil-the-ocean.
2. **Cohesive theme** — password response-echo and email-only recovery.
3. **Explicit B1 deferral** — natural follow-on after credentials-in-source disposition.
4. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
5. **Does not reopen** B1, R5, OAuth, auth_flows, or sensitive_fields.

---

## Frozen signals (selected family)

Runtime maturity today: both default to **Heuristic**. Available under `--profile all` /
`--only`; not on recommended/security explicit allow-lists.

### CWE-549 — Missing Password Field Masking (response echo)

| Field | Value |
|-------|--------|
| File | `reset_recovery.rs` → `detect_cwe_549` |
| Primary signal | SI `"password": pass` + (`gin.H{` or `map[string]string`) |
| Negatives | SI email-only Encode / gin.H email response shapes |
| Span | source find of `"password": pass` |
| Call-facts? | No — JSON sinks fire on safe paths without the echo literal |
| **Proposed disposition** | **fixture-only** |

### CWE-640 — Weak Password Recovery Mechanism

| Field | Value |
|-------|--------|
| File | `reset_recovery.rs` → `detect_cwe_640` |
| Primary signal | SI `ForgotPassword` + `new_password` + `email` + exact password UPDATE |
| Negatives | SI `reset_tokens` / `"token"` / `expires_at` |
| Span | source find of `new_password` |
| Call-facts? | db.Exec / GORM Update alone collide with CWE-620 without corpus co-signals |
| **Proposed disposition** | **fixture-only** |

### Overlap (not duplicates)

| Neighbor | Relation |
|----------|----------|
| **CWE-620** (`auth_flows`) | ChangePassword museum; negative includes `ForgotPassword` → partitions change vs recovery |
| **CWE-941** (`oauth`) | SendResetLink mail notification museum; different sink |
| **CWE-940** (`oauth`) | OAuth state binding; unrelated |
| **CWE-201** (`sensitive_fields`) | APIKey/TokenKey JSON exposure via call_facts; different field museum |

### Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-549** | **fixture-only** | SI password response echo | Neighbor of CWE-201, not duplicate |
| **CWE-640** | **fixture-only** | SI ForgotPassword + email UPDATE | Neighbor of CWE-620/941, not duplicate |

No rule proposed for Heuristic keep or Structural. No deletes. No §1.3 promotion.

---

## Changes

### Code (`credential_lifecycle/reset_recovery.rs` only)

- Proof-boundary comments freezing primary signal, negatives, overlap ownership, and
  disposition.
- **No emit logic, messages, or span changes** (oracle preserved).

### Docs

- `plans/v0.0.6/residual-credential-reset-recovery.md` — checklist complete
- `plans/v0.0.6/evidence-r6-credential-reset-recovery.md` — full evidence
- This PR body (`plans/v0.0.6/pr-r6-credential-reset-recovery.md`)

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs` — propose adding both to `is_fixture_only`
- `src/lang/go/detectors/cwe/source_index.rs` — propose NEEDLES labels (see evidence)
- profiles, `tests/fixtures/manifest.toml`, `cwe-catalog-trust-audit.md`, ledger
- `credentials_in_source.rs`, `key_expiration.rs`, `password_aging.rs`, OAuth, auth_flows
- R5, R7, R8, G*, P1 seams

---

## Integrator proposals

See `plans/v0.0.6/evidence-r6-credential-reset-recovery.md` § Proposed integrator changes.

### Maturity (`maturity.rs`)

Add to `is_fixture_only`: `CWE-549`, `CWE-640`.

### Canary command (worker evidence; re-run after integration)

```sh
cargo build --release --locked
ONLY="CWE-549,CWE-640"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache
done
```

---

## Canary results (2026-07-22)

Release binary built on this branch (`cargo build --release --locked`). Target revisions match
`plans/v0.0.5/canary-corpus.md` pins:

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | 0 |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | 0 |
| **Total** | | **376** | **0** |

Paths: `/home/chinmay/ChinmayPersonalProjects/gopdfsuit`; main-repo
`/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/{monsoon,go-retry,gorl,no-mistakes}`
(worktree has no local `real-repos/`).

Zero useful hits ⇒ fixture-only quarantine is consistent with prior museum families.

---

## Integration

This branch targets `master` for review visibility. When an epic integration branch exists for
v0.0.6 residuals, prefer merging the integration PR to avoid double-merge. Shared maturity /
NEEDLES / audit edits remain integrator-owned per §0.2.

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None in this PR (comments only) |
| **API / CLI** | None until maturity integration |
| **Dependencies** | None |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None in this PR | — |
| Post-integration fixture-only | Still available under `--profile all` / `--only` |

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/reset_recovery.rs` | Signal-freeze comments |
| `plans/v0.0.6/residual-credential-reset-recovery.md` | Checklist complete |
| `plans/v0.0.6/evidence-r6-credential-reset-recovery.md` | Evidence |
| `plans/v0.0.6/pr-r6-credential-reset-recovery.md` | This PR body |

---

## Test plan

- [x] Inventory + selection rationale recorded
- [x] Signal freeze + disposition table + OAuth/reset overlap
- [x] `make lint` — fmt check + clippy clean
- [x] `cargo test --locked --test go_cwe_detector_fixtures` — passed
- [x] `make test` — passed (459/459)
- [x] Two-rule release canary — 0 findings / 376 files
- [x] `git diff --check`

### Commands

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
cargo build --release --locked
# canary as above
git diff --check
```

---

## Related issues

- Closes #163
- Relates to #151
- Plan: `plans/v0.0.6/residual-credential-reset-recovery.md`
- Sibling B1 complete: #107 (`credentials_in_source.rs`)
- Out of scope siblings: R5 expiration/aging, R7, R8, G*, P1

---

## PR metadata checklist

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r6-credential-reset-recovery.md`

---

## Follow-ups (out of scope)

- Integrator maturity / NEEDLES / audit ledger updates
- R5 key_expiration / password_aging residual
- CWE-620 deferred auth_flows subset (if still open after R3)

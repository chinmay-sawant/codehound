# chore(cwe): audit credential expiration/aging trust (R5)

## Summary

- Inventory `credential_lifecycle/key_expiration.rs` + `password_aging.rs`; **select both**
  (**CWE-324**, **CWE-262**, **CWE-263** — combined ~94 lines).
- Freeze primary signals, negatives, fixtures, and maturity state for all three rules.
- Propose **fixture-only** dispositions (integrator applies `maturity.rs` / SourceIndex NEEDLES labels).
- Oracle-safe detector comments only (no emit-path changes); run focused fixtures + three-rule
  real-module canary.

---

## Motivation / context

Residual catalog slice **R5** of issue
[#162](https://github.com/chinmay-sawant/codehound/issues/162). Relates to epic
[#151](https://github.com/chinmay-sawant/codehound/issues/151).

Phase 2 B1 (#107) dispositioned sibling `credentials_in_source.rs`; key expiration and
password aging were explicitly deferred. This worker completes that deferred lifetime-policy
family under the v0.0.6 residual program.

**Integration base SHA:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
**Branch:** `chore/cwe-trust-credential-expiration`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](../v0.0.5/cwe-catalog-trust-audit.md) §1.3  
**Worker contract:** [`parallel-catalog-program.md`](../v0.0.5/parallel-catalog-program.md) §0.2

---

## Selection inventory

### Owner seam — `credential_lifecycle/`

| Leaf | Rules | Lines (approx) | Fixture coverage |
|------|-------|----------------|------------------|
| `credentials_in_source.rs` | CWE-523, 547, 798 | ~154 | stdlib + frameworks each (B1 done) |
| **`key_expiration.rs`** | **CWE-324** | **~41** | **stdlib + frameworks each** |
| **`password_aging.rs`** | **CWE-262, 263** | **~53** | **stdlib + frameworks each** |
| `reset_recovery.rs` | CWE-549, 640 | — | stdlib + frameworks each (R6) |

### Why select both expiration and aging

1. **Combined size is small** — three rules / ~94 lines with full oracle pairs; plan allows both when small.
2. **Cohesive theme** — credential/key lifetime policy museums deferred together from B1.
3. **Explicit B1 deferral** — natural follow-on after credentials-in-source disposition.
4. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
5. **Does not reopen** `credentials_in_source.rs` or `reset_recovery.rs`.

Deferred within this seam (not in this PR): `reset_recovery.rs` (R6).

---

## Frozen signals (selected family)

Runtime maturity today: all three default to **Heuristic**. Available under `--profile all` /
`--only`; not on recommended/security explicit allow-lists.

### CWE-324 — Use of a Key Past its Expiration Date

| Field | Value |
|-------|--------|
| File | `key_expiration.rs` → `detect_cwe_324` |
| Primary signal | SI `ExpiresAt` + (`ApiKeyRow`\|`SigningKey`) + `Secret` + `hmac.New(` + expired-key source |
| Negatives | SI `time.Now().After(row.ExpiresAt)` / `time.Now().After(key.ExpiresAt)` |
| Span | source find of `ExpiresAt` |
| Call-facts? | No — hmac.New alone fires on safe MAC paths |
| **Proposed disposition** | **fixture-only** |

### CWE-262 — Not Using Password Aging

| Field | Value |
|-------|--------|
| File | `password_aging.rs` → `detect_cwe_262` |
| Primary signal | SI `last_seen` \| `changed_at` without age enforcement |
| Negatives | SI `time.Since(` / `maxPasswordAge` |
| Span | source find of `last_seen` else `changed_at` |
| Call-facts? | No — QueryRow/Scan cannot prove missing aging |
| **Proposed disposition** | **fixture-only** |

### CWE-263 — Password Aging with Long Expiration

| Field | Value |
|-------|--------|
| File | `password_aging.rs` → `detect_cwe_263` |
| Primary signal | SI exact `MaxAgeDays: 3650` |
| Negatives | Implicit — safe uses `MaxAgeDays: 90` |
| Span | source find of `MaxAgeDays: 3650` |
| Call-facts? | No — threshold is corpus literal, not API shape |
| **Proposed disposition** | **fixture-only** |

### Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-324** | **fixture-only** | SI ExpiresAt + key-row + hmac | Out-of-unit expiry possible |
| **CWE-262** | **fixture-only** | SI last_seen/changed_at | Org password-policy museum |
| **CWE-263** | **fixture-only** | SI MaxAgeDays: 3650 | Exact ten-year threshold museum |

No rule proposed for Heuristic keep or Structural. No deletes. No §1.3 promotion.

---

## Changes

### Code (`credential_lifecycle/key_expiration.rs`, `password_aging.rs` only)

- Proof-boundary comments freezing primary signal, negatives, call-facts assessment, and
  runtime/deployment assumptions.
- **No emit logic, messages, or span changes** (oracle preserved).

### Docs

- `plans/v0.0.6/residual-credential-expiration.md` — checklist complete
- `plans/v0.0.6/evidence-r5-credential-expiration.md` — full evidence
- This PR body (`plans/v0.0.6/pr-r5-credential-expiration.md`)

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs` — propose adding all three to `is_fixture_only`
- `src/lang/go/detectors/cwe/source_index.rs` — propose NEEDLES labels (see evidence)
- profiles, `tests/fixtures/manifest.toml`, `cwe-catalog-trust-audit.md`, ledger
- `credentials_in_source.rs`, `reset_recovery.rs`
- R1–R4, R6–R8, G*, P1 seams

---

## Integrator proposals

See `plans/v0.0.6/evidence-r5-credential-expiration.md` § Proposed integrator changes.

### Maturity (`maturity.rs`)

Add to `is_fixture_only`: `CWE-324`, `CWE-262`, `CWE-263`.

### Canary command (worker evidence; re-run after integration)

```sh
cargo build --release --locked
ONLY="CWE-324,CWE-262,CWE-263"
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
| `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/key_expiration.rs` | Signal-freeze comments |
| `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/password_aging.rs` | Signal-freeze comments |
| `plans/v0.0.6/residual-credential-expiration.md` | Checklist complete |
| `plans/v0.0.6/evidence-r5-credential-expiration.md` | Evidence |
| `plans/v0.0.6/pr-r5-credential-expiration.md` | This PR body |

---

## Test plan

- [x] Inventory + selection rationale recorded
- [x] Signal freeze + disposition table
- [x] `make lint` — fmt check + clippy clean
- [x] `cargo test --locked --test go_cwe_detector_fixtures` — passed
- [x] `make test` / nextest — 459 passed (load flake on baseline timing under contention; clean on re-run)
- [x] Three-rule release canary — 0 findings / 376 files
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

- Closes #162
- Relates to #151
- Plan: `plans/v0.0.6/residual-credential-expiration.md`
- Sibling B1 complete: #107 (`credentials_in_source.rs`)
- Deferred within seam: `reset_recovery.rs` (R6 / #163)

---

## PR metadata checklist

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r5-credential-expiration.md`

---

## Follow-ups (out of scope)

- `reset_recovery.rs` bounded trust slice (R6)
- Integrator maturity / NEEDLES / audit ledger updates
- Re-run canary on integrated tree after maturity quarantine

# chore(cwe): audit auth_tokens bounded trust (R4)

## Summary

- Inventory `auth_and_validation/auth_tokens.rs`; **select** the whole bounded family
  (**CWE-294**, **CWE-301**, **CWE-303**, **CWE-322**, **CWE-408** — file is ~147 lines).
- Freeze primary signals, negatives, fixtures, and maturity state for all five rules.
- Propose **fixture-only** dispositions (integrator applies `maturity.rs` / SourceIndex NEEDLES labels).
- Oracle-safe detector comments only (no emit-path changes); run focused fixtures + five-rule
  real-module canary.

---

## Motivation / context

Residual catalog slice **R4** of issue
[#161](https://github.com/chinmay-sawant/codehound/issues/161). Relates to epic
[#151](https://github.com/chinmay-sawant/codehound/issues/151).

Phase 2 B3 (#109) dispositioned sibling `cookies.rs`; `auth_tokens.rs` was explicitly
deferred. This worker completes that deferred family under the v0.0.6 residual program.

**Integration base SHA:** `0ff071f6ea0e786b59862be21427a4f83caa78bd`  
**Branch:** `chore/cwe-trust-auth-tokens`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](../v0.0.5/cwe-catalog-trust-audit.md) §1.3  
**Worker contract:** [`parallel-catalog-program.md`](../v0.0.5/parallel-catalog-program.md) §0.2

---

## Selection inventory

### Owner seam — `auth_and_validation/`

| Leaf | Rules | Lines (approx) | Fixture coverage |
|------|-------|----------------|------------------|
| `auth_flows.rs` | CWE-289, 290, 305, 306, 307, 308, 309, 620, 836 | ~289 | stdlib + frameworks each |
| **`auth_tokens.rs`** | **CWE-294, 301, 303, 322, 408** | **~147** | **stdlib + frameworks each** |
| `cookies.rs` | CWE-603, 613 | ~71 | stdlib + frameworks each (B3 done) |

### Why select all five `auth_tokens.rs` rules

1. **File is small enough** — five rules with full oracle pairs; no boil-the-ocean.
2. **Cohesive theme** — token replay, challenge reflection, MAC compare, TLS skip-verify, auth-order.
3. **Explicit B3 deferral** — natural follow-on after cookies disposition.
4. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
5. **Does not reopen** `cookies.rs`, `authorization_and_scoping/`, or `auth_flows.rs`.

Deferred within this seam (not in this PR): `auth_flows.rs`.

---

## Frozen signals (selected family)

Runtime maturity today: all five default to **Heuristic**. Available under `--profile all` /
`--only`; not on recommended/security explicit allow-lists.

### CWE-294 — Authentication Bypass by Capture-replay

| Field | Value |
|-------|--------|
| File | `auth_tokens.rs` → `detect_cwe_294` |
| Primary signal | SI `c.PostForm("auth_token")` / `r.FormValue("auth_token")` |
| Negatives | SI `LoadOrStore(nonce, true)` / `spentNonces` / nonce form loaders |
| Span | source find of `auth_token` |
| Call-facts? | No — replay protection is not a local call shape |
| **Proposed disposition** | **fixture-only** |

### CWE-301 — Reflection Attack in an Authentication Protocol

| Field | Value |
|-------|--------|
| File | `auth_tokens.rs` → `detect_cwe_301` |
| Primary signal | SI exact proof-echo literals (`{"proof": challenge}`, gin H, map literal) |
| Negatives | SI `hmac.New(` / `EncodeToString(` |
| Span | source find of `challenge` |
| Call-facts? | No — reflection requires corpus response literal |
| **Proposed disposition** | **fixture-only** |

### CWE-303 — Incorrect Implementation of Authentication Algorithm

| Field | Value |
|-------|--------|
| File | `auth_tokens.rs` → `detect_cwe_303` |
| Primary signal | SI `hmac.New(` + `mac.Sum(nil)` + `string(expected) == sig` |
| Negatives | Safe uses `subtle.ConstantTimeCompare` (no `== sig` string) |
| Span | source find of `string(expected) == sig` |
| Call-facts? | hmac.New alone fires on safe paths; == sig string is museum boundary |
| **Proposed disposition** | **fixture-only** |

### CWE-322 — Key Exchange without Entity Authentication

| Field | Value |
|-------|--------|
| File | `auth_tokens.rs` → `detect_cwe_322` |
| Primary signal | SI `tls.Dial(` + `InsecureSkipVerify: true` |
| Negatives | Safe uses RootCAs / VerifyHostname |
| Span | source find of `InsecureSkipVerify: true` |
| Call-facts? | tls.Dial alone insufficient without skip literal |
| **Proposed disposition** | **fixture-only** |

### CWE-408 — Incorrect Behavior Order: Early Amplification

| Field | Value |
|-------|--------|
| File | `auth_tokens.rs` → `detect_cwe_408` |
| Primary signal | SI orders SELECT + Authorization + source-order (query before auth) |
| Negatives | Safe checks Authorization before Query |
| Span | source find of SELECT literal |
| Call-facts? | Query + header co-presence without order would FP safe fixture |
| **Proposed disposition** | **fixture-only** |

### Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-294** | **fixture-only** | SI auth_token + nonce negatives | Replay museum |
| **CWE-301** | **fixture-only** | SI proof-echo literals | Challenge reflection museum |
| **CWE-303** | **fixture-only** | SI MAC == sig string | Neighbor of CWE-208/385, not duplicate |
| **CWE-322** | **fixture-only** | SI tls.Dial + skip literal | Sole InsecureSkipVerify owner |
| **CWE-408** | **fixture-only** | SI SQL + Authorization order | Text-order museum |

No rule proposed for Heuristic keep or Structural. No deletes. No §1.3 promotion.

---

## Changes

### Code (`auth_and_validation/auth_tokens.rs` only)

- Proof-boundary comments freezing primary signal, negatives, call-facts assessment, and
  policy-evidence treatment of form/handler/response names.
- **No emit logic, messages, or span changes** (oracle preserved).

### Docs

- `plans/v0.0.6/residual-auth-tokens.md` — checklist complete
- `plans/v0.0.6/evidence-r4-auth-tokens.md` — full evidence
- This PR body (`plans/v0.0.6/pr-r4-auth-tokens.md`)

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs` — propose adding all five to `is_fixture_only`
- `src/lang/go/detectors/cwe/source_index.rs` — propose NEEDLES labels (see evidence)
- profiles, `tests/fixtures/manifest.toml`, `cwe-catalog-trust-audit.md`, ledger
- `auth_flows.rs`, `cookies.rs`, `authorization_and_scoping/`, `file_permissions/`
- R1, R2, R3, R5–R8, G*, P1 seams

---

## Integrator proposals

See `plans/v0.0.6/evidence-r4-auth-tokens.md` § Proposed integrator changes.

### Maturity (`maturity.rs`)

Add to `is_fixture_only`: `CWE-294`, `CWE-301`, `CWE-303`, `CWE-322`, `CWE-408`.

### Canary command (worker evidence; re-run after integration)

```sh
cargo build --release --locked
ONLY="CWE-294,CWE-301,CWE-303,CWE-322,CWE-408"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
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
| **Total** | | **126** | **0** |

Paths: `/home/chinmay/ChinmayPersonalProjects/gopdfsuit`; main-repo
`/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/{monsoon,go-retry}` (worktree has no
local `real-repos/`).

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
| `src/lang/go/detectors/cwe/domains/access_control/auth_and_validation/auth_tokens.rs` | Signal-freeze comments |
| `plans/v0.0.6/residual-auth-tokens.md` | Checklist complete |
| `plans/v0.0.6/evidence-r4-auth-tokens.md` | Evidence |
| `plans/v0.0.6/pr-r4-auth-tokens.md` | This PR body |

---

## Test plan

- [x] Inventory + selection rationale recorded
- [x] Signal freeze + disposition table
- [x] `make lint` — fmt check + clippy clean
- [x] `cargo test --locked --test go_cwe_detector_fixtures` — passed
- [x] `make test` — passed
- [x] Five-rule release canary — 0 findings / 126 files
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

- Closes #161
- Relates to #151
- Plan: `plans/v0.0.6/residual-auth-tokens.md`
- Sibling B3 complete: #109 (`cookies.rs`)
- Deferred within seam: `auth_flows.rs`

---

## PR metadata checklist

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r4-auth-tokens.md`

---

## Follow-ups (out of scope)

- `auth_flows.rs` bounded trust slice
- Integrator maturity / NEEDLES / audit ledger updates
- gorl + no-mistakes expanded canary (integrator re-run on integrated tree)

# Evidence — R6 credential reset / recovery trust

> **Issue:** #163 · **Epic:** #151  
> **Branch:** `chore/cwe-trust-credential-reset`  
> **Integration base:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/reset_recovery.rs`  
> **Selected family file:** `reset_recovery.rs` (whole file)  
> **Deferred from:** Phase 2 B1 (`credentials_in_source` only — see `plans/v0.0.5/evidence-cwe-trust-credential-lifecycle.md`)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Leaf | Rules | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| `credentials_in_source.rs` | CWE-523, 547, 798 | ~95 | stdlib + frameworks × vulnerable/safe | B1 done (#107) |
| `key_expiration.rs` | CWE-324 | ~41 | stdlib + frameworks × vulnerable/safe | Out of scope (R5) |
| `password_aging.rs` | CWE-262, 263 | ~53 | stdlib + frameworks × vulnerable/safe | Out of scope (R5) |
| **`reset_recovery.rs`** | **CWE-549, 640** | **~67** | **stdlib + frameworks × vulnerable/safe** | **Yes (R6)** |

### Why select the whole `reset_recovery.rs` file

1. **File is small enough** — two rules with full oracle pairs; no boil-the-ocean risk.
2. **Cohesive theme** — password response-echo and weak email-only recovery share the reset/recovery museum.
3. **Explicit B1 deferral** — natural follow-on after credentials-in-source disposition.
4. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
5. **Does not reopen** B1 credentials-in-source, R5 expiration/aging, OAuth, or auth_flows.

---

## Freeze inventory (selected family)

Runtime maturity today: both default to **Heuristic** (`maturity_for` has no explicit fixture-only entry). Available under `--profile all` / `--only`; not on recommended/security explicit allow-lists.

| Rule | Fixtures | Primary signals (frozen) | Negatives | Source span |
|------|----------|----------------------------|-----------|-------------|
| **CWE-549** | 4 files | SI `"password": pass` + (`gin.H{` **or** `map[string]string`) | SI `Encode(map[string]string{"email": email})` / gin.H email-only response | `source.find("\"password\": pass")` |
| **CWE-640** | 4 files | SI `ForgotPassword` + `new_password` + `email` + (`UPDATE users SET password` **or** GORM `Where("email = ?", email).Update("password", newPass)`) | SI `reset_tokens` / `"token"` / `expires_at` | `source.find("new_password")` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact password response echo | `"password": pass` | 549 |
| Response wrapper tokens | `gin.H{`, `map[string]string` | 549 |
| Email-only safe responses | `Encode(map[string]string{"email": email})`, gin.H email-only | 549 (neg) |
| Recovery helper name | `ForgotPassword` | 640 |
| New-password form / JSON field | `new_password` | 640 |
| Exact password UPDATE sinks | `UPDATE users SET password`, GORM email Where+Update | 640 |
| Tokenized recovery markers | `reset_tokens`, `"token"`, `expires_at` | 640 (neg) |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-549 | Password reflection inferred from exact `"password": pass` map literal, not from JSON field dataflow | Museum response shape → fixture-only |
| CWE-640 | Weak recovery inferred from ForgotPassword + email-only UPDATE without token co-signals in same unit | Unit-local museum; cannot prove distributed token store → fixture-only |

---

## Overlap vs existing OAuth / reset CWE families

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Password change without current password | **CWE-620** (`auth_flows.rs`; R3 deferred subset) | Neighbor, not duplicate. 620 targets `ChangePassword` + `"new_password"` UPDATE; its negative **includes** `ForgotPassword`, partitioning change vs recovery. |
| OAuth callback without state | **CWE-940** (`oauth.rs`, fixture-only) | Different sink (`oauth_tokens` INSERT); no shared needles with 549/640. |
| Reset-link email notification | **CWE-941** (`oauth.rs`, fixture-only) | SendResetLink + `smtp.SendMail` + email query museum; different proof boundary (mail sink, not password UPDATE). |
| Invoice IDOR | **CWE-639** (`scoping.rs`, fixture-only) | Unrelated authorization/scoping museum (name collision only with “reset” theme in prose). |
| Sensitive JSON field exposure | **CWE-201** (`sensitive_fields.rs`, R2 keep-Heuristic) | Neighbor: APIKey/TokenKey record→JSON via call_facts; 549 is password-preview echo museum. |
| Credentials-in-source | **CWE-523/547/798** (`credentials_in_source.rs`, B1) | Sibling leaf; not reopened. |

**Verdict:** no ownership collision. CWE-620 and CWE-640 intentionally partition via the `ForgotPassword` negative on 620. CWE-941 owns reset *notification*, not recovery *authorization*.

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-549 | **No.** `c.JSON` / `json.Encode` fire on safe email-only responses; only the exact `"password": pass` literal is the defect boundary. | Leave SI primary; **fixture-only** |
| CWE-640 | **No.** `db.Exec` / GORM `Update` are production-shaped but cannot prove email-only recovery without ForgotPassword + new_password corpus co-signals (and would collide with CWE-620). | Leave SI primary; **fixture-only** |

No oracle-safe call_facts rewrite in this PR — rewrites would not strengthen the proof boundary while preserving oracle (same bar as B1 credentials-in-source and R4 auth_tokens).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-549 | **fixture-only** (proposed) | Exact `"password": pass` response-echo museum |
| CWE-640 | **fixture-only** (proposed) | Exact ForgotPassword + email-only UPDATE museum |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

File: `credential_lifecycle/reset_recovery.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ownership overlap, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

Add to `is_fixture_only`:

```text
CWE-549, CWE-640
```

Unit-test assertions mirroring other fixture-only families.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `"password": pass` | `fixture-literal: CWE-549` (already present unlabeled) |
| `gin.H{`, `map[string]string` | leave unlabeled or comment dual-use (generic wrappers) |
| `Encode(map[string]string{"email": email})` | `negative-gate: CWE-549` |
| `gin.H{\n\t\t"email": c.PostForm("email"),\n\t})` | `negative-gate: CWE-549` (exact safe shape) |
| `ForgotPassword` | `fixture-literal: CWE-640` (also CWE-620 negative) |
| `new_password` | dual-use with CWE-620; label carefully or leave |
| `UPDATE users SET password` | `fixture-literal: CWE-640` |
| `Where("email = ?", email).Update("password", newPass)` | `fixture-literal: CWE-640` |
| `reset_tokens`, `"token"`, `expires_at` | `negative-gate: CWE-640` |

### Fixture / manifest / findings-oracle

- None (oracle unchanged; no new `.txt` files).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-549,CWE-640 \
  --format json --json-envelope --no-fail --no-cache
```

Re-run on the integrated tree; worker canary is evidence, not final proof.

Per `plans/v0.0.5/canary-corpus.md`, scan gopdfsuit + real-repos (monsoon, go-retry, gorl, no-mistakes).

---

## Canary (worker pre-integration) — 2026-07-22

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | **0** |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | **0** |

**Totals:** 376 scanned files. Per-rule: CWE-549 ×0, CWE-640 ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-549,CWE-640"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch-r6.json
  python3 -c "import json; d=json.load(open('/tmp/ch-r6.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

---

## Validation

| Gate | Result |
|------|--------|
| `make lint` | pass |
| `cargo test --locked --test go_cwe_detector_fixtures` | pass (includes both ×4 fixture pairs) |
| `make test` | pass (459/459; transient load-flake on timing budgets under parallel release build, clean on quiet retry) |
| `git diff --check` | pass |

# Evidence — R5 credential expiration / aging trust

> **Issue:** #162 · **Epic:** #151  
> **Branch:** `chore/cwe-trust-credential-expiration`  
> **Integration base:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/`  
> **Selected family files:** `key_expiration.rs` + `password_aging.rs` (whole files)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Leaf | Rules | Lines (approx) | Fixture coverage | Selected? |
|------|-------|----------------|------------------|-----------|
| **`key_expiration.rs`** | **CWE-324** | **~41** | stdlib + frameworks × vulnerable/safe | **Yes** |
| **`password_aging.rs`** | **CWE-262, 263** | **~53** | stdlib + frameworks × vulnerable/safe | **Yes** |
| `credentials_in_source.rs` | CWE-523, 547, 798 | ~154 | stdlib + frameworks each | B1 done (#107) |
| `reset_recovery.rs` | CWE-549, 640 | — | stdlib + frameworks each | Deferred (R6) |

**Total selected:** ~94 lines, 3 rules. Plan allows both when small; fixtures cover all three.

### Why select both expiration and aging

1. **Combined size is small** — 94 lines with full oracle pairs; no boil-the-ocean risk.
2. **Cohesive theme** — credential/key lifetime policy museums deferred together from B1.
3. **Explicit B1 deferral** — natural follow-on after credentials-in-source disposition.
4. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
5. **Does not reopen** `credentials_in_source.rs` or `reset_recovery.rs`.

### Why not split further

| Alternative | Reason rejected |
|-------------|-----------------|
| Expiration only (324) | Leaves 262/263 as a micro-slice; combined still under the "both if small" bar |
| Aging only (262/263) | Leaves 324 orphaned; same theme deferred together in B1 evidence |

---

## Freeze inventory (selected family)

Runtime maturity today: all three default to **Heuristic** (`maturity_for` has no explicit fixture-only / structural entry). Available under `--profile all` / `--only`; not on recommended/security explicit allow-lists.

| Rule | Fixtures | Primary signals (frozen) | Negatives | Source span |
|------|----------|----------------------------|-----------|-------------|
| **CWE-324** | 4 files | SI `ExpiresAt` + (`ApiKeyRow`\|`SigningKey`) + `Secret` + `hmac.New(` + (`Add(-48 * time.Hour)` \| `ExpiresAt time.Time`) | SI `time.Now().After(row.ExpiresAt)` / `time.Now().After(key.ExpiresAt)` | `source.find("ExpiresAt")` |
| **CWE-262** | 4 files | SI `last_seen` \| `changed_at` | SI `time.Since(` / `maxPasswordAge` | `source.find("last_seen")` else `changed_at` |
| **CWE-263** | 4 files | SI exact `MaxAgeDays: 3650` | Implicit — safe uses `MaxAgeDays: 90` | `source.find("MaxAgeDays: 3650")` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Key expiry field | `ExpiresAt`, `ExpiresAt time.Time` | 324 |
| Key-row museum types | `ApiKeyRow`, `SigningKey`, `Secret` | 324 |
| Crypto co-signal | `hmac.New(` | 324 |
| Expired-key construction | `Add(-48 * time.Hour)` | 324 |
| Expiry check (negative) | `time.Now().After(row.ExpiresAt)`, `time.Now().After(key.ExpiresAt)` | 324 |
| Age metadata columns | `last_seen`, `changed_at` | 262 |
| Age enforcement (negative) | `time.Since(`, `maxPasswordAge` | 262 |
| Excessively long max-age literal | `MaxAgeDays: 3650` | 263 |
| Reasonable max-age (implicit neg) | `MaxAgeDays: 90` | 263 |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-324 | Key expiry may be enforced outside the unit (gateway, KMS, remote key service) | Unit-local absence of After check ≠ proof of expired-key use → fixture-only |
| CWE-262 | Password rotation windows are org policy; last_seen/changed_at often used for analytics without age reject | Not project-agnostic security sink → fixture-only |
| CWE-263 | "Excessively long" max age is org policy; proof is the exact 3650-day museum literal | Threshold museum → fixture-only |

---

## Existing CWE / BP / PERF ownership

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Hard-coded JWT/session const | **CWE-547** (`credentials_in_source.rs`, fixture-only) | Neighbor: hard-coded secret const vs key-expiry museum |
| Embedded DSN password | **CWE-798** (fixture-only, B1) | Different sink |
| Cleartext login transport | **CWE-523** (fixture-only, B1) | Different sink |
| Password reset / recovery | **reset_recovery.rs** (R6 deferred) | Sibling leaf; not reopened |
| MAC == sig / ConstantTimeCompare | **CWE-303** (`auth_tokens.rs`, R4) | Neighbor crypto compare; 324 owns ExpiresAt+hmac shape |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-324 | **No.** `hmac.New` fires on every legitimate MAC path; expiry proof requires corpus ExpiresAt + row-type co-signals. | Leave SI primary; **fixture-only** |
| CWE-262 | **No.** QueryRow/Scan alone cannot prove missing aging without column-name corpus; would FP analytics loads. | Leave SI primary; **fixture-only** |
| CWE-263 | **No.** Integer field assignment alone cannot encode "too long" without the exact 3650 museum. | Leave SI primary; **fixture-only** |

No oracle-safe call_facts rewrite in this PR — rewrites would not strengthen the proof boundary while preserving oracle (same bar as B1 credentials-in-source and R4 auth_tokens).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-324 | **fixture-only** (proposed) | ExpiresAt + key-row + hmac museum; out-of-unit expiry possible |
| CWE-262 | **fixture-only** (proposed) | last_seen/changed_at without aging — org policy museum |
| CWE-263 | **fixture-only** (proposed) | Exact `MaxAgeDays: 3650` threshold museum |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

Files: `credential_lifecycle/key_expiration.rs`, `password_aging.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ownership, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

Add to `is_fixture_only`:

```text
CWE-324, CWE-262, CWE-263
```

Unit-test assertions mirroring other fixture-only families.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `ExpiresAt`, `ApiKeyRow`, `SigningKey`, `Add(-48 * time.Hour)`, `ExpiresAt time.Time` | `fixture-literal: CWE-324` |
| `time.Now().After(row.ExpiresAt)`, `time.Now().After(key.ExpiresAt)` | `negative-gate: CWE-324` |
| `hmac.New(`, `Secret` (in 324 context) | leave unlabeled or comment dual-use with other crypto rules |
| `last_seen`, `changed_at` | `fixture-literal: CWE-262` |
| `time.Since(`, `maxPasswordAge` | `negative-gate: CWE-262` |
| `MaxAgeDays: 3650` | `fixture-literal: CWE-263` |

### Fixture / manifest / findings-oracle

- None (oracle unchanged; no new `.txt` files).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-324,CWE-262,CWE-263 \
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

**Totals:** 376 scanned files. Per-rule: all three ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-324,CWE-262,CWE-263"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch-r5.json
  python3 -c "import json; d=json.load(open('/tmp/ch-r5.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

---

## Validation

| Gate | Result |
|------|--------|
| `make lint` | pass |
| `cargo test --locked --test go_cwe_detector_fixtures` | pass (includes all 3×4 fixture pairs) |
| `make test` / nextest | pass (459 passed; earlier parallel-load flake on `engine_baseline_io` timing — passes in isolation and on re-run) |
| `git diff --check` | pass |

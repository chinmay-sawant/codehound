# Evidence — B1 Credential-lifecycle trust (credentials-in-source)

> **Issue:** #107 · **Epic:** #105 · **Phase 2 integration:** #111  
> **Branch:** `chore/cwe-trust-credential-lifecycle`  
> **Integration base:** `9d66183c3b29d8589317328170226bff6d4323d1`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/credentials_and_secrets/credential_lifecycle/`  
> **Selected family file:** `credentials_in_source.rs`  
> **Date:** 2026-07-21

---

## Family inventory and selection

| Leaf | Rules | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| `credentials_in_source.rs` | CWE-523, 547, 798 | ~95 | stdlib + frameworks × vulnerable/safe | **Yes** |
| `key_expiration.rs` | CWE-324 | ~41 | stdlib + frameworks × vulnerable/safe | Deferred |
| `password_aging.rs` | CWE-262, 263 | ~53 | stdlib + frameworks × vulnerable/safe | Deferred (expiration sibling) |
| `reset_recovery.rs` | CWE-549, 640 | ~67 | stdlib + frameworks × vulnerable/safe | Deferred |

### Why select credentials-in-source

1. **Cohesive single-file family** — three rules share the “credentials live in / are accepted from insecure source” theme (cleartext login transport, hard-coded signing constants, hard-coded DSN).
2. **Completes prior Tranche 1 work** — CWE-798 is already `fixture-only`; siblings 523/547 still lack an explicit Phase-2 disposition.
3. **Unambiguous museum signals** — exact paths, const names, and one literal DSN; dispositions do not require structural promotion debate under §1.3.
4. **Clear ownership vs siblings** — does not reopen password_storage (Phase 1 / CWE-1052 bootstrap DSN), transport CWE-319 (payment fields + ListenAndServe), or BP-152 (retired-duplicate of CWE-798).
5. **Bounded size** — three rules, full oracle pairs, fits one worktree evidence slice without subsetting.

### Why defer the other families

| Deferred | Reason |
|----------|--------|
| **Expiration** (`key_expiration` + `password_aging`) | Mixes crypto key-expiry (324: `ExpiresAt` + `hmac.New` + `ApiKeyRow`/`SigningKey`) with password-policy museums (262: `last_seen`/`changed_at`; 263: exact `MaxAgeDays: 3650`). Better as a later single-theme slice. |
| **Reset/recovery** (549/640) | Cohesive but smaller residual; 549 is response-echo of `"password": pass` (neighbor of information-exposure), 640 is email-only ForgotPassword without token. Leave intact for a follow-on issue. |

---

## Freeze inventory (selected family)

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-523** | 4 files (frameworks + stdlib vulnerable/safe) | Heuristic (default; not in `is_fixture_only`) | Eligible via Heuristic for non-allow-list packs; not on recommended/security explicit allow-lists | SI: `/login` + `password` + (`Addr: ":8080"` **or** `StartCleartextLogin`) | SI: `requireTLS(` / `Request.TLS == nil` / `r.TLS == nil` |
| **CWE-547** | 4 files | Heuristic (default) | Same | SI: `const jwtSecret = ` **or** `const sessionMACKey = ` | SI: `os.Getenv("JWT_SIGNING_KEY")` / `os.Getenv("SESSION_MAC_KEY")` |
| **CWE-798** | 4 files | **FixtureOnly** (Tranche 1) | Quarantined from recommended/security default packs | Exact source text: `postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable` | SI: `os.Getenv("REPORTING_DSN")` |

**Source spans:** `source.find` on `/login` (or `password`), `const jwtSecret = ` / `const sessionMACKey = `, and the exact DSN string.

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact route / helper names | `/login`, `StartCleartextLogin`, `requireTLS(` | 523 |
| Cleartext listen literals | `Addr: ":8080"` | 523 |
| Exact security-relevant const names | `const jwtSecret = `, `const sessionMACKey = ` | 547 |
| Env-load safe paths | `JWT_SIGNING_KEY`, `SESSION_MAC_KEY`, `REPORTING_DSN` | 547, 798 |
| One literal DSN with embedded password | `postgres://reporting:Tr4ck3rP@ss@…` | 798 |
| Generic co-signal | bare `password` (with `/login`) | 523 |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-523 | Cleartext is inferred from `Addr: ":8080"` or helper name, not from actual TLS config / reverse-proxy topology | Deployment-sensitive; unit-local TLS proof is incomplete → fixture-only |
| CWE-547 | Const *name* implies security-relevant secret (jwt/session MAC); no type or secret-scanner proof | Identifier museum → fixture-only |
| CWE-798 | One corpus DSN is the entire credential proof | Already fixture-only |

---

## Existing CWE / BP / PERF ownership

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Cleartext listen + payment fields | **CWE-319** (`secrets_and_transport/transport.rs`, fixture-only; call_facts ListenAndServe) | Neighbor, not duplicate. 523 is login-credential acceptance without TLS middleware; 319 is card CVV/Number + cleartext listen. |
| Process-wide token cache | **CWE-524** (fixture-only, Phase 1 A2) | Different sink (map cache vs login path). |
| Hard-coded DSN at bootstrap | **CWE-1052** (`password_storage/bootstrap.rs`) | Different DSN shape (`password=SuperSecret99` + gorm/sql Open). Phase 1 password_storage out of scope. |
| Hard-coded credentials BP | **BP-152** | Already **retire-duplicate** of CWE-798 (`bp-candidates-disposition.md`). |
| Test DSN markers | **BP-161** | Tests only; not this CWE detector. |
| PERF rules | none | No PERF ownership of hard-coded secrets / cleartext login. |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-523 | **No.** TLS enforcement and cleartext acceptance are middleware / deployment properties. `ListenAndServe` / `http.Server` alone collides with CWE-319 and lacks login-credential proof without corpus co-signals. | Leave SI primary; **fixture-only** |
| CWE-547 | **No.** Hard-coded const *is* the defect; `hmac.New` / JWT `SignedString` fire on legitimate env-loaded keys and do not prove the constant is security-relevant without fixture const names. | Leave SI primary; **fixture-only** |
| CWE-798 | **No.** `sql.Open` / `sqlx.Connect` is not hard-coded-credential proof; only the exact DSN string is. | Keep SI/source-text primary; **fixture-only** (already) |

No oracle-safe call_facts rewrite in this PR — rewrites would not strengthen the proof boundary while preserving oracle (same bar as A4 comment-only freeze and CWE-256 needle-primary keep).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-523 | **fixture-only** (proposed) | Exact `/login` + cleartext Addr/helper museum; deployment TLS topology not unit-local; avoid CWE-319 collision |
| CWE-547 | **fixture-only** (proposed) | Exact `jwtSecret` / `sessionMACKey` const-name museum; no generalized hard-coded-secret proof |
| CWE-798 | **keep fixture-only** | One literal reporting DSN; Tranche 1 disposition reaffirmed |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

File: `credential_lifecycle/credentials_in_source.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ownership, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-523`, `CWE-547` to `is_fixture_only`.
- Leave `CWE-798` in `is_fixture_only` (already present).
- Update maturity unit tests accordingly.
- Do **not** add any of these to the structural allow-list.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `/login` | leave unlabeled or comment dual-use (too common as a path token alone; 523 requires co-signals) |
| `StartCleartextLogin` | `fixture-literal` (CWE-523 pure helper) |
| `Addr: ":8080"` | not currently a NEEDLES entry (matched via SI has on full string only if present — verify; currently used via `source_index.has` so it must be in NEEDLES or substring index) — if present unlabeled, label `fixture-literal` (CWE-523) |
| `requireTLS(` | `negative-gate` (CWE-523) |
| `Request.TLS == nil` / `r.TLS == nil` | `negative-gate` (CWE-523) if present in NEEDLES |
| `const jwtSecret = ` | `fixture-literal` (CWE-547 frameworks) |
| `const sessionMACKey = ` | `fixture-literal` (CWE-547 pure) |
| `os.Getenv("JWT_SIGNING_KEY")` | `negative-gate` (CWE-547) |
| `os.Getenv("SESSION_MAC_KEY")` | `negative-gate` (CWE-547) |
| `os.Getenv("REPORTING_DSN")` | `negative-gate` (CWE-798) |
| exact reporting DSN string | not in NEEDLES (matched via `source.contains`); optional `fixture-literal` if ever indexed |
| bare `password` | leave unlabeled (too generic) |

### Fixture / manifest / findings-oracle

- None (oracle unchanged; no new `.txt` files).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-523,CWE-547,CWE-798 \
  --format json --json-envelope --no-fail --no-cache
```

Re-run on the integrated tree (`chore/epic-105-phase2-integration`); worker canary is evidence, not final proof.

### Audit ledger update (integrator)

Record family selection + dispositions + canary in `plans/v0.0.5/cwe-catalog-trust-audit.md` and check off §2.1 in `parallel-catalog-program.md` after Phase 2 batch merge.

---

## Canary (worker pre-integration) — 2026-07-21

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |

**Totals:** 126 scanned files. Per-rule: CWE-523 ×0, CWE-547 ×0, CWE-798 ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-523,CWE-547,CWE-798"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit real-repos/monsoon real-repos/go-retry; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch.json
  python3 -c "import json; d=json.load(open('/tmp/ch.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

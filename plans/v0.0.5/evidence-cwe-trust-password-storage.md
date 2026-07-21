# Evidence — A1 Password-storage trust (CWE-256 / 257 / 261 / 916)

> **Issue:** #96 · **Epic:** #95  
> **Branch:** `chore/cwe-trust-password-storage`  
> **Integration base:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/credentials_and_secrets/password_storage/hashing.rs`  
> **Date:** 2026-07-21

---

## Freeze inventory

| Rule | Fixtures (frameworks + stdlib) | Maturity today | Profile eligibility today | Primary signals (pre-rewrite) |
|------|--------------------------------|----------------|---------------------------|-------------------------------|
| CWE-256 | 4 files (`-vulnerable`/`-safe` × frameworks/stdlib) | Heuristic (default; not in `is_fixture_only`) | Eligible for default packs via Heuristic; not on recommended/security allow-lists unless matched by pack patterns | Exact GORM `Password: c.PostForm("password")` **or** exact SQL `db.Exec("INSERT INTO credentials(login, pass) VALUES(?, ?)", login, pass)`; negatives: `GenerateFromPassword(`, `hashPassphrase(`, `digest`, `hash` |
| CWE-257 | 4 files | Heuristic (default) | Same | SI: `aes.NewCipher(` + `cipher.NewGCM(` + `gcm.Seal(` + `base64.StdEncoding.EncodeToString(` + (`"password": encoded` **or** `VALUES(?, ?)", login, encoded)`) |
| CWE-261 | 4 files | Heuristic (default) | Same | SI: `base64.StdEncoding.EncodeToString(` + (`Secret: encoded` **or** `Store(user, encoded)`) |
| CWE-916 | 4 files | Heuristic (default) | Same | SI: `md5.Sum(` + `password`; negatives: `bcrypt.GenerateFromPassword`, `hashIterations = 100_000` |

**Source spans (pre-rewrite):** `source.find` on the primary needle (`Password: c.PostForm…` / SQL, `aes.NewCipher(`, `base64…EncodeToString(`, `md5.Sum(`).

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, audit ledger, parallel program.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact persistence text | `Password: c.PostForm("password")`; `db.Exec("INSERT INTO credentials…", login, pass)`; `"password": encoded`; `VALUES(?, ?)", login, encoded)`; `Secret: encoded`; `Store(user, encoded)` | 256, 257, 261 |
| Password naming | bare `password` co-signal; field names `Password` / `Secret` | 916 (and 256/257/261 via shapes) |
| AES / base64 storage shapes | `aes.NewCipher` + `cipher.NewGCM` + `.Seal` + `base64.StdEncoding.EncodeToString` | 257, 261 |
| Fixed iteration markers | `hashIterations = 100_000` (safe negative); bcrypt `GenerateFromPassword` | 916 |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-256 | **No** without dataflow from password form field → Create/Exec sink. GORM struct field assignment and exact SQL arg shapes are not complete call-fact password-storage proofs. | Leave needle/source-text primary; **fixture-only** |
| CWE-257 | **Partial.** Crypto APIs (`aes.NewCipher`, `cipher.NewGCM`, `.Seal`, `base64.StdEncoding.EncodeToString`) are complete call-fact sinks; password-storage boundary still needs exact persistence co-signals. | Oracle-safe rewrite: call_facts primary for crypto; SI co-signals retained → still **fixture-only** |
| CWE-261 | **Partial.** `base64.StdEncoding.EncodeToString` is a complete call-fact sink; storage proof is exact `Secret: encoded` / `Store(user, encoded)`. | Same pattern → **fixture-only** |
| CWE-916 | **Yes for the sink** (mirrors CWE-328 `md5.Sum`). Domain co-signal `password` + safe-path negatives remain SI. | Oracle-safe rewrite: call_facts primary → **keep Heuristic** |

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-256 | **fixture-only** | Exact GORM/SQL persistence museum; no generalized password→store dataflow |
| CWE-257 | **fixture-only** | Crypto chain is production-shaped and call_facts-primary after rewrite, but emit still gated on exact `"password": encoded` / SQL `encoded` corpus shapes |
| CWE-261 | **fixture-only** | Base64 encode alone is not password storage; emit gated on exact Secret/Store corpus shapes |
| CWE-916 | **keep Heuristic** | `md5.Sum` call_facts primary (stdlib); real-module gopdfsuit hits on PDF owner/user password MD5; not structural (§1.3: bare `password` co-signal + fixed iteration negative) |

**No Structural promotion** for any rule in this family.

---

## Oracle-safe detector rewrites (this PR)

File: `password_storage/hashing.rs` only.

- **CWE-256:** comments + freeze documentation only (needle-primary retained).
- **CWE-257:** SI impossibility prefilter + persistence co-signals; primary = call_facts for AES-GCM + base64 encode; span = `aes.NewCipher` call start.
- **CWE-261:** SI prefilter + storage co-signals; primary = call_facts `base64.StdEncoding.EncodeToString`; span = that call.
- **CWE-916:** SI prefilter + `password` co-signal + bcrypt/iteration negatives; primary = call_facts `md5.Sum`; span = that call.

Fixture oracle preserved (vulnerable fire, safe silence). No fixture renames; no new proposed fixture files required.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-256`, `CWE-257`, `CWE-261` to `is_fixture_only`.
- Leave `CWE-916` as default **Heuristic** (not structural allow-list).

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `Password: c.PostForm("password")` | `fixture-literal` (CWE-256 GORM plaintext) |
| `GenerateFromPassword(` | `negative-gate` (CWE-256 hashed-path) |
| `hashPassphrase(` | `negative-gate` (CWE-256 pure hashed-path) |
| `VALUES(?, ?)", login, encoded)` | `fixture-literal` (CWE-257 pure persistence) |
| `"password": encoded` | `fixture-literal` (CWE-257 frameworks persistence; already in NEEDLES) |
| `aes.NewCipher(` | already `negative-gate` (CWE-1240); dual-use as CWE-257 prefilter — comment may note CWE-257 |
| `base64.StdEncoding.EncodeToString(` | `negative-gate` / prefilter (CWE-257 / CWE-261) |
| `Secret: encoded` | `fixture-literal` (CWE-261 frameworks) |
| `Store(user, encoded)` | `fixture-literal` (CWE-261 pure) |
| `md5.Sum(` | already `negative-gate` (CWE-328 / CWE-916 prefilter) |
| `bcrypt.GenerateFromPassword` | `negative-gate` (CWE-916 safe-path) |
| `hashIterations = 100_000` | `fixture-literal` (CWE-916 pure safe stretch) |
| bare `digest` / `hash` / `password` | too generic — leave unlabeled |

### Fixture / manifest / findings-oracle

- No new fixtures; no manifest wiring.
- Findings-oracle impact: none expected on fixtures; real-module canary shows CWE-916 ×2 on gopdfsuit (pre-existing shape; not introduced by this rewrite).

### Canary command (integrator re-run after batch merge)

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit real-repos/monsoon real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-256,CWE-257,CWE-261,CWE-916 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', d.get('findingCount')); print('files', d.get('stats',{}).get('files_scanned')); print([(f.get('rule_id'), f.get('file'), f.get('line')) for f in d.get('findings',[])])"
done
```

---

## Canary results (worker pre-integration) — 2026-07-21

Source revision: branch `chore/cwe-trust-password-storage` after hashing rewrite.  
Release binary: `cargo build --release --locked`.

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **2** (CWE-916 ×2) |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-256 ×0, CWE-257 ×0, CWE-261 ×0, CWE-916 ×2.

**Sample hit paths (gopdfsuit):**

- `CWE-916` `internal/pdf/encryption/encrypt.go:79` — `md5.Sum` in PDF owner-password hash (`computeOwnerHash`)
- `CWE-916` `internal/pdf/redact/encryption_inhouse.go:241` — iterative `md5.Sum` in PDF password-derived key material

**Decision:** quarantine CWE-256 / 257 / 261 as fixture-only (integrator). Keep CWE-916 Heuristic with reviewed real-module PDF-password MD5 hits; **do not** promote to Structural. Zero hits on 256/257/261 support museum quarantine, not deletion. Fixture coverage retained as regression evidence.

---

## Validation

- [x] `cargo test --locked --test go_cwe_detector_fixtures` — 4 passed
- [x] `make lint` — passed
- [x] `make test` — 443 passed + 1 doctest
- [x] Release canary — recorded above

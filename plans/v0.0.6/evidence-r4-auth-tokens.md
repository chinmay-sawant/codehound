# Evidence — R4 auth_tokens bounded trust

> **Issue:** #161 · **Epic:** #151  
> **Branch:** `chore/cwe-trust-auth-tokens`  
> **Integration base:** `0ff071f6ea0e786b59862be21427a4f83caa78bd`  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/access_control/auth_and_validation/auth_tokens.rs`  
> **Selected family file:** `auth_tokens.rs` (whole file)  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Rule | Lines (fn) | Fixture coverage | Primary signal class | Selected? |
|------|------------|------------------|----------------------|-----------|
| **CWE-294** | ~38 | stdlib + frameworks vulnerable/safe | SI auth_token loaders + nonce negatives | **Yes** |
| **CWE-301** | ~30 | stdlib + frameworks vulnerable/safe | SI proof-echo literals + HMAC negative | **Yes** |
| **CWE-303** | ~22 | stdlib + frameworks vulnerable/safe | SI hmac.New + mac.Sum + `string(expected) == sig` | **Yes** |
| **CWE-322** | ~19 | stdlib + frameworks vulnerable/safe | SI tls.Dial + `InsecureSkipVerify: true` | **Yes** |
| **CWE-408** | ~29 | stdlib + frameworks vulnerable/safe | SI orders SELECT + Authorization + source order | **Yes** |

**Total seam file:** ~147 lines, 5 rules. Deferred sibling within `auth_and_validation/`: `auth_flows.rs` (9 rules, ~289 lines).

### Why select the whole `auth_tokens.rs` file

1. **File is small enough** — five rules with full oracle pairs fit one bounded slice; no boil-the-ocean risk per plan checklist item 4.
2. **Cohesive theme** — authentication token/challenge/MAC/TLS/auth-order defects share the “auth protocol implementation” boundary.
3. **Deferred from B3** — `cookies.rs` was dispositioned in #109; `auth_tokens.rs` was explicitly deferred and is the natural follow-on.
4. **Full fixture oracle** — stdlib + frameworks vulnerable/safe for every rule; no new fixtures required.
5. **Unambiguous museum shapes** — exact form field names, response literals, MAC comparison string, TLS config literal, and orders SQL.

### Why defer `auth_flows.rs`

| Deferred | Reason |
|----------|--------|
| **auth_flows.rs** (CWE-289, 290, 305–309, 620, 836) | 9 rules / ~289 lines; login/MFA/session-flow museum distinct from token/challenge/MAC slice; better as a separate bounded issue. |

---

## Freeze inventory (selected family)

Runtime maturity today: all five default to **Heuristic** (`maturity_for` has no explicit fixture-only / structural entry). Available under `--profile all` / `--only`; not on recommended/security explicit allow-lists.

| Rule | Fixtures | Primary signals (frozen) | Negatives | Source span |
|------|----------|----------------------------|-----------|-------------|
| **CWE-294** | 4 files | SI `c.PostForm("auth_token")` / `r.FormValue("auth_token")` | SI `LoadOrStore(nonce, true)` / `spentNonces` / nonce form loaders | `source.find("auth_token")` |
| **CWE-301** | 4 files | SI `gin.H{"proof": challenge}` / `{"proof": challenge}` / `map[string]string{"proof": challenge}` | SI `hmac.New(` / `EncodeToString(` | `source.find("challenge")` |
| **CWE-303** | 4 files | SI `hmac.New(` + `mac.Sum(nil)` + `string(expected) == sig` | Safe uses `subtle.ConstantTimeCompare` (no `== sig` string) | `source.find("string(expected) == sig")` |
| **CWE-322** | 4 files | SI `tls.Dial(` + `InsecureSkipVerify: true` | Safe uses RootCAs / VerifyHostname (no skip literal) | `source.find("InsecureSkipVerify: true")` |
| **CWE-408** | 4 files | SI `SELECT * FROM orders WHERE tenant_id = ?` + `Authorization` + query before auth in source | Safe checks Authorization before Query | `source.find(SELECT…)` |

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact form field loaders | `auth_token`, `nonce`, `challenge`, `relay_host` | 294, 301, 322 |
| Exact response / proof literals | `{"proof": challenge}`, gin H proof echo | 301 |
| Exact MAC comparison museum | `string(expected) == sig` | 303 |
| HMAC compute co-signals | `hmac.New(`, `mac.Sum(nil)` | 301 (neg), 303 |
| TLS skip-verify literal | `InsecureSkipVerify: true` with `tls.Dial(` | 322 |
| Exact SQL + header order | `SELECT * FROM orders WHERE tenant_id = ?` before `Authorization` | 408 |
| Replay-tracking markers | `LoadOrStore(nonce, true)`, `spentNonces` | 294 (neg) |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-294 | Replay inferred from missing nonce co-signals in same unit, not cross-request store analysis | Unit-local; cannot prove distributed replay protection → fixture-only |
| CWE-301 | Challenge reflection inferred from exact proof-echo literal shapes | Museum response shape → fixture-only |
| CWE-303 | MAC misuse limited to exact `string(expected) == sig` pattern | Does not catch hex-decode + == or hmac.Equal misuse elsewhere → fixture-only |
| CWE-322 | Skip-verify requires `tls.Dial(` co-presence (relay fixture shape) | Narrower than all InsecureSkipVerify uses but still corpus-bound → fixture-only |
| CWE-408 | Auth order from source byte offsets in one function, not CFG/inter-procedural order | Text-order museum → fixture-only |

---

## Existing CWE / BP / PERF ownership

| Concern | Owner | Relation to this family |
|---------|-------|-------------------------|
| Early-exit byte-loop compare | **CWE-208**, **CWE-385** (`crypto_comparison.rs`) | Neighbor, not duplicate. 303 targets `string(expected) == sig` MAC museum; 208/385 target loop early-exit patterns. |
| OAuth token INSERT museum | **CWE-639** area (`oauth.rs`, fixture-only) | Different sink (`oauth_tokens` INSERT vs auth_token form replay). |
| Destructive HMAC webhook | **CWE-347** area (`destructive.rs`) | Different proof (`X-Signature` + hmac shapes for destructive ops). |
| Cookie/session auth | **CWE-603/613** (`cookies.rs`, B3 done) | Sibling family; not reopened. |
| Login/MFA flows | **auth_flows.rs** (deferred) | Different museum (login handlers, MFA, lockout). |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-294 | **No.** FormValue/PostForm alone cannot prove missing replay protection without corpus auth_token + nonce co-signals. | Leave SI primary; **fixture-only** |
| CWE-301 | **No.** json.Encode / map literal alone cannot prove challenge reflection without exact proof-echo literals. | Leave SI primary; **fixture-only** |
| CWE-303 | **No.** `hmac.New` fires on safe MAC paths; only the `string(expected) == sig` string is the defect boundary. | Leave SI primary; **fixture-only** |
| CWE-322 | **No.** `tls.Dial` is common; skip-verify proof requires exact `InsecureSkipVerify: true` corpus literal. | Leave SI primary; **fixture-only** |
| CWE-408 | **No.** `db.Query` + Authorization header co-presence without source-order check would false-positive safe fixture. | Leave SI + source-order primary; **fixture-only** |

No oracle-safe call_facts rewrite in this PR — rewrites would not strengthen the proof boundary while preserving oracle (same bar as B3 cookies and B1 credentials-in-source).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-294 | **fixture-only** (proposed) | Exact auth_token loader + nonce-tracking museum |
| CWE-301 | **fixture-only** (proposed) | Exact challenge→proof echo literals |
| CWE-303 | **fixture-only** (proposed) | Exact `string(expected) == sig` MAC comparison museum |
| CWE-322 | **fixture-only** (proposed) | tls.Dial + InsecureSkipVerify literal museum |
| CWE-408 | **fixture-only** (proposed) | Exact orders SQL + Authorization source-order museum |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

File: `auth_and_validation/auth_tokens.rs` only.

- Module + per-rule freeze comments documenting signals, negatives, ownership, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

Add to `is_fixture_only`:

```text
CWE-294, CWE-301, CWE-303, CWE-322, CWE-408
```

Unit-test assertions mirroring other fixture-only families.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `c.PostForm("auth_token")`, `r.FormValue("auth_token")` | `fixture-literal: CWE-294` |
| `LoadOrStore(nonce, true)`, `spentNonces`, `PostForm("nonce")`, `FormValue("nonce")` | `negative-gate: CWE-294` |
| `gin.H{"proof": challenge}`, `{"proof": challenge}`, `map[string]string{"proof": challenge}` | `fixture-literal: CWE-301` |
| `hmac.New(`, `EncodeToString(` (in 301 neg context) | `negative-gate: CWE-301` |
| `string(expected) == sig` | `fixture-literal: CWE-303` |
| `mac.Sum(nil)` (with 303) | leave unlabeled or comment dual-use with 301 neg |
| `tls.Dial(`, `InsecureSkipVerify: true` | `fixture-literal: CWE-322` |
| `SELECT * FROM orders WHERE tenant_id = ?` | `fixture-literal: CWE-408` |
| `Authorization` | leave unlabeled (too generic alone) |

### Fixture / manifest / findings-oracle

- None (oracle unchanged; no new `.txt` files).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-294,CWE-301,CWE-303,CWE-322,CWE-408 \
  --format json --json-envelope --no-fail --no-cache
```

Re-run on the integrated tree; worker canary is evidence, not final proof.

Per `plans/v0.0.5/canary-corpus.md`, scan gopdfsuit + real-repos (monsoon, go-retry minimum; gorl + no-mistakes when pinned).

---

## Canary (worker pre-integration) — 2026-07-22

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |

**Totals:** 126 scanned files. Per-rule: all five ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-294,CWE-301,CWE-303,CWE-322,CWE-408"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch-r4.json
  python3 -c "import json; d=json.load(open('/tmp/ch-r4.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

---

## Validation

| Gate | Result |
|------|--------|
| `make lint` | pass |
| `cargo test --locked --test go_cwe_detector_fixtures` | pass (includes all 5×4 fixture pairs) |
| `make test` | pass |
| `git diff --check` | pass |

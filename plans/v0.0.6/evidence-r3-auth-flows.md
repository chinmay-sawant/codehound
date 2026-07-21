# Evidence — R3 auth_flows bounded trust (login identity)

> **Issue:** #160 · **Epic:** #151  
> **Branch:** `chore/cwe-trust-auth-flows`  
> **Integration base:** `0ff071f` (origin/master @ 2026-07-22)  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/access_control/auth_and_validation/auth_flows.rs`  
> **Selected subfamily:** login identity trust — **CWE-289**, **CWE-290**  
> **Date:** 2026-07-22

---

## Family inventory and selection

| Rule | Theme | Approx. lines | Fixture coverage | Selected? |
|------|-------|---------------|------------------|-----------|
| **CWE-289** | Alternate-name auth bypass (realm strip) | ~22 | stdlib + frameworks × vulnerable/safe | **Yes** |
| **CWE-290** | Spoofing auth bypass (trusted header) | ~24 | stdlib + frameworks × vulnerable/safe | **Yes** |
| CWE-305 | Debug flag before subject check | ~30 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-306 | Destructive action without auth gate | ~26 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-307 | Login without throttling/lockout | ~36 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-308 | High-value action without MFA | ~36 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-309 | Enterprise login without WebAuthn | ~42 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-620 | Password change without current password | ~32 | stdlib + frameworks × vulnerable/safe | Deferred |
| CWE-836 | Password hash accepted as credential | ~34 | stdlib + frameworks × vulnerable/safe | Deferred |

### Why select login identity trust (289 + 290)

1. **Smallest cohesive subfamily** — two rules sharing “caller-controlled or stripped identity accepted as authenticated principal”; matches Phase 2 B3 cookies pattern (2 rules per slice).
2. **Phase-3 optional split alignment** — `auth_flows_login.rs (289, 290)` was the named login-identity partition; distinct from bruteforce (305–309) and password (620, 836) themes.
3. **Existing fixture oracle** — full vulnerable/safe pairs for stdlib and frameworks; no new fixtures required.
4. **Unambiguous museum shapes** — exact `"@")[0]` split subscript (289) and exact `X-Remote-User` header name (290); route/handler naming treated as policy evidence per worker contract.
5. **Does not reopen** `file_permissions/` or `authorization_and_scoping/` (A4 complete).

### Why defer the other seven rules

| Deferred group | Reason |
|----------------|--------|
| **Bruteforce / MFA gaps** (305–309) | Five rules mixing debug bypass, missing auth gates, rate limits, MFA, and WebAuthn — better as one later “auth hardening” slice or further subsetting. |
| **Password credential flows** (620, 836) | Cohesive pair but separate theme (credential update/verification); leave for follow-on R3 sibling or dedicated issue. |

---

## Freeze inventory (selected subfamily)

| Rule | Fixtures | Maturity today | Profile eligibility today | Primary signals (frozen) | Negatives |
|------|----------|----------------|---------------------------|--------------------------|-----------|
| **CWE-289** | 4 files (frameworks + stdlib vulnerable/safe) | Heuristic (default; not in `is_fixture_only`) | Eligible via Heuristic for non-allow-list packs; not on recommended/security explicit allow-lists | SI: `strings.Split(` + `"@")[0]` without `canonical_name = ?` | SI: `canonical_name = ?` |
| **CWE-290** | 4 files | Heuristic (default) | Same | **call_facts** `c.GetHeader` / `r.Header.Get` with `X-Remote-User` first arg | Safe fixtures omit header read (session cookie path); no explicit emit-path negative |

**Source spans:** `source.find("strings.Split(")` (289); `header_call.start_byte` from call_facts (290).

**Shared surfaces not edited (worker contract):** `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`.

---

## Corpus signal classes

| Class | Examples | Rules |
|-------|----------|-------|
| Exact split subscript museum | `"@")[0]` with `strings.Split(` | 289 |
| Realm-aware principal lookup | `canonical_name = ?` | 289 (negative) |
| Exact spoofable header name | `X-Remote-User` in Header.Get / GetHeader arg | 290 |
| Call-facts header read | `r.Header.Get`, `c.GetHeader` | 290 |
| Generic co-signals | `strings.Split(` alone (too broad without `"@")[0]`) | 289 |

---

## Runtime / deployment assumptions

| Rule | Assumption | Trust impact |
|------|------------|--------------|
| CWE-289 | Realm stripping is inferred from exact split subscript text, not from dataflow proving the split result reaches auth | Unit-local alias proof incomplete → fixture-only |
| CWE-290 | Header name `X-Remote-User` implies reverse-proxy trust boundary; no proof the header is unset/untrusted in deployment | Header naming is policy evidence → fixture-only |

---

## Existing CWE / BP ownership

| Concern | Owner | Relation to this subfamily |
|---------|-------|----------------------------|
| Client-side auth header trust | **CWE-603** (cookies.rs, fixture-only B3) | Neighbor: billing UPDATE trusts `X-Authenticated`; 290 is identity-from-header without session. |
| Session cookie issues | **CWE-613** (cookies.rs, fixture-only B3) | Safe 290 fixture uses session cookie — negative by omission, not shared detector gate. |
| Authorization / scoping | **authorization_and_scoping/** (A4 complete) | Out of scope; not reopened. |
| JWT / token auth | **auth_tokens.rs** (deferred R4 sibling) | Different seam file. |

---

## Call-facts primary analysis

| Rule | Can call_facts be complete primary? | Decision |
|------|-------------------------------------|----------|
| CWE-289 | **No.** `strings.Split` is ubiquitous; only the exact `"@")[0]` museum subscript plus absence of `canonical_name = ?` identifies the defect. | Leave SI primary; **fixture-only** |
| CWE-290 | **Partial.** call_facts locates the header read, but emit still requires exact `X-Remote-User` string in the argument — policy/corpus marker, not generalized spoofable-header proof. | Keep call_facts + corpus header name; **fixture-only** |

No oracle-safe emit-path rewrite in this PR — comments only (same bar as B3 cookies freeze).

---

## Per-rule disposition

| Rule | Disposition | Rationale |
|------|-------------|-----------|
| CWE-289 | **fixture-only** (proposed) | Exact `"@")[0]` + principals SQL museum; no generalized realm-alias proof |
| CWE-290 | **fixture-only** (proposed) | Exact `X-Remote-User` header name museum; call_facts partial; deployment trust boundary not unit-local |

**No Structural promotion.** No Heuristic keep (no generalized production-shaped sink with real-module signal under §1.3).

---

## Detector changes this PR

File: `auth_and_validation/auth_flows.rs` — **CWE-289 and CWE-290 only**.

- Module + per-rule freeze comments documenting signals, negatives, ownership, and disposition.
- **No emit-path / span / needle changes** — fixture oracle preserved bit-for-bit.

No new fixture `.txt` files. No `manifest.toml` edits.

---

## Proposed integrator changes (DO NOT apply on this branch)

### Maturity (`src/rules/maturity.rs`)

- Add `CWE-289`, `CWE-290` to `is_fixture_only`.
- Update maturity unit tests accordingly.
- Do **not** add either to the structural allow-list.

### NEEDLES labels (`source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `"@")[0]` | `fixture-literal` (CWE-289) |
| `canonical_name = ?` | `negative-gate` (CWE-289) |
| `strings.Split(` | leave unlabeled (too generic alone) |
| `X-Remote-User` | not in NEEDLES (matched via call_facts arg); optional comment if indexed later |

### Fixture / manifest / findings-oracle

- None (oracle unchanged).

### Exact canary command

```sh
target/release/codehound TARGET --profile all \
  --only CWE-289,CWE-290 \
  --format json --json-envelope --no-fail --no-cache
```

Re-run on integrated tree after maturity merge; worker canary is evidence, not final proof.

### Audit ledger update (integrator)

Record subfamily selection + dispositions + canary in `plans/v0.0.5/cwe-catalog-trust-audit.md` after Phase 2 residual batch merge (epic #151 integration).

---

## Canary (worker pre-integration) — 2026-07-22

Release binary built on this branch (`cargo build --release --locked`). Target revisions match
[`canary-corpus-pins.json`](../v0.0.5/canary-corpus-pins.json):

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | **0** |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | **0** |

**Totals:** 376 scanned files. Per-rule: CWE-289 ×0, CWE-290 ×0.

Zero real-module hits confirms museum/fixture-only shapes; no Heuristic-keep signal under §1.3.

```sh
ONLY="CWE-289,CWE-290"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache > /tmp/ch-r3.json
  python3 -c "import json; d=json.load(open('/tmp/ch-r3.json')); print(d.get('stats',{}).get('files_scanned'), len(d.get('findings') or []))"
done
```

**Note:** Worktree has no local `real-repos/`; scans used main-checkout absolute paths (identical revisions to pin manifest).

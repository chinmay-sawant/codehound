# v0.0.5 — CWE Catalog Trust Audit, Tranche 1

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2
> **Status:** Tranche 1 complete (PRNG + CWE-798 quarantined). Tranche 2 complete (cipher misuse: CWE-1204/1240 fixture-only; CWE-325 stays Heuristic). §2.3 call-facts rewrites for CWE-325/328 done. Tranche 3 long-tail NEEDLES/maturity (§2.4): CWE-323/331/347 fixture-only; CWE-328 stays Heuristic. Tranche 4 OAuth authorization-bypass (§2.5): CWE-940/941 fixture-only; CWE-941 call-facts primary for `smtp.SendMail`. Further long-tail NEEDLES audit and maturity expansion remain under GitHub issue [#39](https://github.com/chinmay-sawant/codehound/issues/39). The remaining CWE catalog is not yet certified.
> **Estimated effort:** Incremental, rule-family by rule-family; do not bulk-promote or bulk-check the remaining catalog.

---

## Overview

This audit keeps the Go CWE catalog honest. It separates rules that can support ordinary CI use from exact corpus patterns that remain useful only under `--profile all`.

---

## Executive Summary

The first tranche confirms that CWE-334, CWE-335, CWE-338, CWE-342, CWE-343, and CWE-798 must remain `fixture-only`. Their current implementations depend on exact numeric bounds, identifier names, formulas, or a literal DSN rather than generalized call/type/flow evidence. They are already excluded from recommended and security profiles; this audit records why and adds an explicit promotion bar for future structural rules.

Tranche 2 extends the same bar to the cipher-misuse family: CWE-1204 and CWE-1240 are corpus-literal detectors and are now `fixture-only`; CWE-325 is a production-shaped stdlib API smell kept as **Heuristic** without structural promotion (needle-primary emit). A zero-hit real-module canary (0/126 files) supports keep/quarantine rather than delete.

Tranche 3 covers crypto-strength siblings and JWT manual decode: CWE-323 / CWE-331 / CWE-347 quarantine as `fixture-only` (fixed nonce identifiers, recovery-code bound, exact JWT variable names); CWE-328 (`md5.Sum`) stays **Heuristic** with three reviewed gopdfsuit hits and no structural promotion.

Tranche 4 covers OAuth authorization-bypass long-tail: CWE-940 / CWE-941 quarantine as `fixture-only` (OAuthCallback / SendResetLink helper names, exact `oauth_tokens` INSERT, `[]string{email}` recipient shape). CWE-941 is rewritten to `call_facts` primary for `smtp.SendMail` without structural promotion.

Success means every future `structural` promotion has generalized syntax or facts, negative coverage, and real-module evidence. A CWE rule is not promoted merely because a fixture fires.

---

## Phase 1: Known Fixture-Only Rules

### 1.1 Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-334 | Exact `Intn(4096)` bound | Keep `fixture-only` |
| CWE-335 | Exact `seed` naming plus wall-clock PRNG source shapes | Keep `fixture-only` |
| CWE-338 | Exact `sid` / `token` naming plus `math/rand` source shapes | Keep `fixture-only` |
| CWE-342 | Exact `lastOTP` / `lastSmsCode` identifiers | Keep `fixture-only` |
| CWE-343 | Exact recurrence formulas from the corpus | Keep `fixture-only` |
| CWE-798 | One literal PostgreSQL DSN | Keep `fixture-only` |

- [x] Verify the six rules remain excluded from recommended and security packs.
- [x] Record the source evidence for their quarantine rather than treating their fixture coverage as product proof.
- [x] Audit the remaining long-tail rules in domain-sized tranches; create an explicit disposition for every rule changed or promoted. **Tranche 2 cipher family done** (§2.2); further domain-sized tranches remain under [#39](https://github.com/chinmay-sawant/codehound/issues/39).

### 1.2 Canary decision — 2026-07-18

The six-rule family was run from CodeHound source revision
`ecab267207d4cff9a7dd814d5b9f4bc975e2e78e` after `cargo build --release
--locked`. The target revisions and results were:

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

All three used this command shape (with the target path substituted):

```sh
target/release/codehound TARGET --profile all \
  --only CWE-334,CWE-335,CWE-338,CWE-342,CWE-343,CWE-798 \
  --format json --json-envelope --no-fail --no-cache
```

It produced **0 useful hits / 126 scanned files**.

**Decision (2026-07-18):** keep the family available only through `--profile
all` and retain its fixture coverage as regression evidence. Do not promote it,
and do not delete it solely for this zero-hit canary; review it again only when
a detector has generalized evidence meeting the structural promotion bar.

- [x] Record the canary rate and a dated zero-useful-hit disposition for this completed family.

### 1.3 Structural promotion bar

A CWE rule may be promoted to `structural` only when all of the following are true:

- The primary match uses AST shape, call facts, callee classification, or taint flow—not a project-specific identifier, literal path, magic value, or exact fixture formula.
- Source-index needles, if retained, are only negative prefilters; they cannot be the evidence that emits the finding.
- Vulnerable and safe fixtures cover a renamed/structurally varied near miss.
- A reviewed real-module hit demonstrates that the rule is actionable or that its false-positive boundary is documented.
- The maturity-table entry and profile eligibility are updated in the same change.

---

## Phase 2: Incremental Rewrite Candidates

Remaining open items are in scope for GitHub issue [#39](https://github.com/chinmay-sawant/codehound/issues/39). The CWE-918 call-facts pilot below is already recorded; do not treat the whole tranche as complete.

- [x] Select one long-tail detector whose call facts already provide a complete primary signal, then replace its primary `SourceIndex.has` logic without changing its finding oracle. **Done for CWE-918** (see §2.1); **CWE-325 + CWE-328** follow-on rewrites in §2.3; **CWE-941** (`smtp.SendMail`) in §2.5. Further rewrites stay issue-gated under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Retain only API/stdlib needles that can cheaply prove a detector impossible; label fixture-only corpus literals in the source index as they are audited. **Tranche 2 cipher family labeled** (see §2.2); **Tranche 3 crypto-strength/JWT family labeled** (see §2.4); **Tranche 4 OAuth family labeled** (see §2.5); remaining NEEDLES pass continues incrementally under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Record a canary hit-rate and a dated keep/narrow/quarantine/delete decision for each completed family; Tranche 1 PRNG family (§1.2), Tranche 2 cipher family (§2.2), Tranche 3 crypto-strength/JWT family (§2.4), and Tranche 4 OAuth family (§2.5) are recorded. Further families remain under [#39](https://github.com/chinmay-sawant/codehound/issues/39).

### 2.1 Call-facts pilot — CWE-918 (2026-07-18)

**Rule:** `detect_cwe_918` in `src/lang/go/detectors/cwe/domains/request_handling.rs`.

**Before:** Primary emit required exact SourceIndex needles `http.Get(target)` plus `c.Query("url")` / `r.URL.Query().Get("url")`.

**After:** Primary match iterates `facts.call_facts` for callee `http.Get` whose argument uses a `UserControlled` `input_bindings` name whose assignment expression is a `url` query read (`Query("url")` / `Get("url")` via assignment facts). SourceIndex is retained only as:
- cheap impossibility prefilter: `http.Get(`
- negative prefilters: `allowedHosts` / `allowedHostsPure` / `Hostname()` (host allowlisting evidence)

**Oracle:** Existing CWE-918 vulnerable fixtures still fire; safe fixtures still silence (allowlist negatives + `http.Get(parsed.String())` is not a user-binding argument). Neighbor fixtures such as CWE-494 (`http.Get(url)` from `bundle_url`) must not newly fire CWE-918. No fixture renames.

**Canary:** Not run in this pilot change; fixture regression is the oracle gate.

### 2.2 Tranche 2 — Cipher misuse long-tail (CWE-325 / CWE-1204 / CWE-1240)

> **Domain:** `src/lang/go/detectors/cwe/domains/cryptography/ciphers.rs`
> **Date:** 2026-07-18
> **Issue:** [#39](https://github.com/chinmay-sawant/codehound/issues/39)
> **Scope:** Remaining non-PRNG cryptography-domain detectors that are still needle-primary. PRNG rules (334/335/338/342/343) and CWE-798 were Tranche 1; CWE-918 is the separate call-facts pilot in §2.1.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-325 | `cipher.NewCTR(` + `XORKeyStream(` without `cipher.NewGCM(` / `Seal(` | Keep **Heuristic**. Stdlib API tokens are production-shaped negative-gate/prefilter needles. **Superseded by §2.3** call-facts primary rewrite (still not structural-promoted). |
| CWE-1204 | Exact IV literal `1234567890123456` plus `weakIV` / `weakIVPure` identifiers | Quarantine **fixture-only**. Corpus-specific fixed IV, not a general static-IV fact. |
| CWE-1240 | `SealSessionToken(` / `xorCipher(` helper names plus `^ key` body shape | Quarantine **fixture-only**. Project-specific helper identifiers, not a generalized custom-cipher detector. |

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `1234567890123456` | `fixture-literal` (CWE-1204 fixed IV) |
| `weakIV` / `weakIVPure` | `fixture-literal` (CWE-1204 identifiers) |
| `SealSessionToken(` / `SealSessionTokenPure(` | `fixture-literal` (CWE-1240 helpers) |
| `xorCipher(` / `xorCipherPure(` | `fixture-literal` (CWE-1240 helpers) |
| `^ key` | `fixture-literal` (CWE-1240 XOR body) |
| `cipher.NewCTR(` / `XORKeyStream(` | `negative-gate` (CWE-325 prefilter) |
| `cipher.NewCBCEncrypter(` | `negative-gate` (CWE-1204 prefilter) |
| `cipher.NewGCM(` / `aes.NewCipher(` / `Seal(` / `aead.Seal(` | `negative-gate` (safe-path / AEAD prefilters) |
| `io.ReadFull(rand.Reader, iv)` / `io.ReadFull(rand.Reader, nonce)` | `negative-gate` (crypto/rand safe-path) |

#### Maturity table

- `CWE-1204`, `CWE-1240` added to `is_fixture_only` in `src/rules/maturity.rs`.
- `CWE-325` remains default **Heuristic** (not on the structural allow-list).
- Structural promotion bar from §1.3 is **not** met for any rule in this family.

#### Canary decision — 2026-07-18

Source revision at documentation time: `d5ec79acb2f42de9d9dccffbb7f62b04bf25442f` (release binary used for hit-count measurement; detector oracle for these three rules is needle-stable). Target revisions match Tranche 1:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-325,CWE-1204,CWE-1240 \
  --format json --json-envelope --no-fail --no-cache
```

**0 useful hits / 126 scanned files** (78+43+5). Per-rule counts: CWE-325 ×0, CWE-1204 ×0, CWE-1240 ×0.

**Decision (2026-07-18):** keep CWE-1204 and CWE-1240 available only through `--profile all` (fixture-only quarantine). Keep CWE-325 as Heuristic without structural promotion. Do not delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit CWE-325 only when call-fact/AST primary evidence meets §1.3.

#### Next long-tail candidates (not in this tranche)

- Crypto-strength siblings + JWT manual decode: audited in **§2.4** (CWE-323/331/347 fixture-only; CWE-328 keep Heuristic after §2.3 rewrite).
- Transport TLS: CWE-319 (`http.ListenAndServe` / `ListenAndServeTLS` / `tls.Config` — still needle-primary domain scope).
- Continue NEEDLES-comment pass only within domain-sized families; do not bulk-edit the index.

### 2.3 Call-facts rewrites — CWE-325 + CWE-328 (2026-07-18)

> **Issue:** [#39](https://github.com/chinmay-sawant/codehound/issues/39)
> **Scope:** Second call-facts primary rewrite tranche after the CWE-918 pilot (§2.1). Prefer production-shaped stdlib APIs already extracted into `call_facts`.

#### CWE-325 — Missing Cryptographic Step (CTR without AEAD)

**Rule:** `detect_cwe_325` in `src/lang/go/detectors/cwe/domains/cryptography/ciphers.rs`.

**Before:** Needle-primary emit on `SourceIndex.has("cipher.NewCTR(")` + `XORKeyStream(` without `cipher.NewGCM(` / `Seal(`; span via `source.find("cipher.NewCTR(")`.

**After:** Primary match requires both callees in `facts.call_facts`:
- `cipher.NewCTR`
- any callee ending with `.XORKeyStream` (receiver name varies: `stream`, …)

SourceIndex is retained only as:
- cheap impossibility prefilter: `cipher.NewCTR(` + `XORKeyStream(`
- negative prefilters: `cipher.NewGCM(` / `Seal(` (AEAD path)

Finding span uses `ctr_call.start_byte` from call facts.

**Oracle:** Existing CWE-325 vulnerable fixtures still fire; safe fixtures still silence (GCM + Seal negatives). No fixture renames. Maturity remains **Heuristic** (not promoted to structural — no real-module hit evidence yet; §1.3 bar still not met).

**Canary:** Not re-run in this rewrite; fixture regression is the oracle gate. Prior zero-hit canary for the cipher family is in §2.2.

#### CWE-328 — Weak Hash (MD5)

**Rule:** `detect_cwe_328` in `src/lang/go/detectors/cwe/domains/general_security/crypto_and_integrity/crypto_strength.rs`.

**Before:** Needle-primary emit on `SourceIndex.has("md5.Sum(")` with span via `source.find("md5.Sum(")`.

**After:** Primary match iterates `facts.call_facts` for callee `md5.Sum`. SourceIndex is retained only as a cheap impossibility prefilter: `md5.Sum(`. Finding span uses `md5_call.start_byte`.

**Oracle:** Existing CWE-328 vulnerable fixtures still fire; safe fixtures (SHA-256 + salt) still silence. Neighbor CWE-916 (`md5.Sum` + `password` needle-primary for insufficient work factor) is unchanged. No fixture renames. Maturity remains **Heuristic**.

**NEEDLES label:** `md5.Sum(` labeled `negative-gate` (CWE-328 / CWE-916 prefilter) in `source_index.rs`.

**Canary:** Not run in this rewrite; fixture regression is the oracle gate.

#### Disposition summary

| Rule | Primary evidence after rewrite | Disposition |
|---|---|---|
| CWE-325 | `call_facts` (`cipher.NewCTR` + `.XORKeyStream`); SI prefilter/negative only | Keep **Heuristic**; not structural-promoted |
| CWE-328 | `call_facts` (`md5.Sum`); SI prefilter only | Keep **Heuristic**; not structural-promoted |

### 2.4 Tranche 3 — Crypto-strength + JWT long-tail NEEDLES/maturity (CWE-323 / CWE-328 / CWE-331 / CWE-347)

> **Domains:** `src/lang/go/detectors/cwe/domains/general_security/crypto_and_integrity/crypto_strength.rs` (323/328/331); `src/lang/go/detectors/cwe/domains/cryptography/jwt.rs` (347)
> **Date:** 2026-07-18
> **Issue:** [#39](https://github.com/chinmay-sawant/codehound/issues/39)
> **Scope:** Long-tail NEEDLES/maturity audit for the crypto-strength siblings and JWT manual-decode candidates listed after Tranche 2. CWE-328 call-facts rewrite is separately recorded in §2.3; this section records dispositions, needle labels, maturity quarantine, and the real-module canary.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-323 | Exact identifiers `sharedNonce` / `relaySessionNonce` plus literals `fixednonce12` / `static-nonce12`, with `aead.Seal(` and without `io.ReadFull(rand.Reader, nonce)` | Quarantine **fixture-only**. Corpus-specific fixed-nonce names/literals, not a general static-nonce fact. |
| CWE-328 | `call_facts` primary for callee `md5.Sum` (after §2.3); SI `md5.Sum(` prefilter only | Keep **Heuristic**. Production-shaped stdlib API + three reviewed gopdfsuit hits. **Not promoted** to structural (§1.3 still wants broader evidence/negative coverage beyond this canary). |
| CWE-331 | Exact `Intn(900000) + 100000` bound + `rand.NewSource(time.Now().UnixNano())` + co-presence `code` | Quarantine **fixture-only**. Fixture recovery-code range (same museum class as CWE-334 `Intn(4096)`). |
| CWE-347 | Exact `strings.Split(raw, ".")` + `DecodeString(parts[1])` + `json.Unmarshal(payload, &claims)` without `VerifyPKCS1v15(` / `invalid signature` | Quarantine **fixture-only**. Exact fixture variable names (`raw` / `parts` / `payload` / `claims`); not a generalized JWT-without-verify AST/call-fact detector. |

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `sharedNonce` / `relaySessionNonce` | `fixture-literal` (CWE-323 identifiers) |
| `fixednonce12` / `static-nonce12` | `fixture-literal` (CWE-323 fixed-nonce byte literals) |
| `aead.Seal(` / `io.ReadFull(rand.Reader, nonce)` | already `negative-gate` (CWE-323 prefilter / safe-path; left as-is) |
| `md5.Sum(` | already `negative-gate` from §2.3 rewrite (CWE-328 / CWE-916 prefilter) |
| `Intn(900000) + 100000` | `fixture-literal` (CWE-331 recovery-code bound) |
| `rand.NewSource(time.Now().UnixNano())` (+ related wall-clock seed shapes) | `fixture-literal` (CWE-331 / PRNG family seed shapes) |
| `strings.Split(raw, ".")` / `DecodeString(parts[1])` / `json.Unmarshal(payload, &claims)` | `fixture-literal` (CWE-347 / CWE-358 JWT corpus shape) |
| `VerifyPKCS1v15(` | `negative-gate` (CWE-347 safe-path prefilter) |
| `invalid signature` | `fixture-literal` (CWE-347 safe-path error string) |

Note: bare `code` co-presence token for CWE-331 is too generic to label; left unlabeled.

#### Maturity table

- `CWE-323`, `CWE-331`, `CWE-347` added to `is_fixture_only` in `src/rules/maturity.rs`.
- `CWE-328` remains default **Heuristic** (aligned with §2.3; not on the structural allow-list).
- Structural promotion bar from §1.3 is **not** met for any rule in this family.

#### Canary decision — 2026-07-18

Source revision near documentation time: `1f68bab0dd418b4a5dadf73a534a2c8a5ef4199a` (release binary used for hit-count measurement; detector oracles needle-/call-fact stable for these rules — maturity quarantine only affects default packs). Target revisions match Tranche 1/2:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 3 (all CWE-328) |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-323,CWE-328,CWE-331,CWE-347 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-323 ×0, CWE-328 ×3, CWE-331 ×0, CWE-347 ×0.

CWE-328 real-module hits (gopdfsuit):

| File | Line |
|---|---:|
| `internal/pdf/encryption/encrypt.go` | 79 |
| `internal/pdf/generator.go` | 1051 |
| `internal/pdf/redact/encryption_inhouse.go` | 241 |

These are genuine `md5.Sum` call sites (PDF encryption/redact paths already noted in impact notes), so they support keep-Heuristic rather than fixture-only quarantine.

**Decision (2026-07-18):** quarantine CWE-323, CWE-331, and CWE-347 as fixture-only (`--profile all` only). Keep CWE-328 as Heuristic without structural promotion (consistent with §2.3 rewrite). Do not delete needles solely for the zero-hit fixture-only members; retain fixture coverage as regression evidence. Revisit CWE-328 only when §1.3 structural bar is fully met; revisit 323/331/347 only when evidence is generalized beyond corpus identifiers/bounds/variable names.

#### Next long-tail candidates (not in this tranche)

- Continue NEEDLES-comment pass only within domain-sized families; do not bulk-edit the index.
- Transport TLS: CWE-319 (still needle-primary).
- Other needle-primary long-tail still defaulting to Heuristic without a dated disposition (JWT neighbors such as CWE-358, further crypto/auth strength rules) remain under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- OAuth / authorization-bypass long-tail audited in **§2.5** (CWE-940/941 fixture-only; CWE-941 call-facts primary for `smtp.SendMail`).

### 2.5 Tranche 4 — OAuth authorization-bypass long-tail (CWE-940 / CWE-941)

> **Domain:** `src/lang/go/detectors/cwe/domains/general_security/authorization_bypass/oauth.rs`
> **Date:** 2026-07-18
> **Issue:** [#39](https://github.com/chinmay-sawant/codehound/issues/39)
> **Scope:** OAuth / caller-directed notification long-tail still needle-primary after Tranche 3. Prefer domain is listed under pending issue work (oauth / `smtp.SendMail`). CWE-941 call-facts rewrite is recorded here; both rules are maturity-quarantined as fixture-only.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-940 | Exact helpers `OAuthCallback(` / `OAuthCallbackPure(` plus `INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)` and bare `code`, without OAuth state cookie / `invalid oauth state` | Quarantine **fixture-only**. Project-specific callback helper names and exact SQL shape, not a generalized OAuth-state AST/call-fact detector. |
| CWE-941 | After rewrite: `call_facts` primary for callee `smtp.SendMail`; SI still requires `SendResetLink(` / `SendResetLinkPure(` + `Query("email")` / `Query().Get("email")` + `[]string{email}` without `user.Email` / `lookupEmail(` / `sessionUserID` | Quarantine **fixture-only**. Stdlib SMTP sink is production-shaped and call-facts primary, but emit still depends on fixture helper names and exact recipient-slice text. **Not** structural-promoted (§1.3 bar not met). |

#### Call-facts rewrite — CWE-941

**Rule:** `detect_cwe_941` in `oauth.rs`.

**Before:** Needle-primary emit on `SendResetLink(` / `SendResetLinkPure(` + `smtp.SendMail` + email query + `[]string{email}`; span via source find on the email query.

**After:** Primary match iterates `facts.call_facts` for callee `smtp.SendMail`. SourceIndex is retained as:
- cheap impossibility prefilter: `smtp.SendMail`
- corpus co-signals (oracle): `SendResetLink(` / `SendResetLinkPure(`, `Query("email")` / `Query().Get("email")`, `[]string{email}`
- negative prefilters: `user.Email` / `lookupEmail(` / `sessionUserID`

Finding span uses `send_call.start_byte` from call facts.

**Oracle:** Existing CWE-941 vulnerable fixtures still fire; safe fixtures still silence (session/stored-email negatives). Neighbor fixtures that use `smtp.SendMail` without the SendResetLink + query-email + `[]string{email}` co-shape must not newly fire. No fixture renames. Maturity is **fixture-only** (not Heuristic — helper names dominate).

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `OAuthCallback(` / `OAuthCallbackPure(` | `fixture-literal` (CWE-940 helpers) |
| `INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)` | `fixture-literal` (CWE-940 SQL shape) |
| `oauth_state` / `Cookie("oauth_state")` / `r.Cookie("oauth_state")` | `negative-gate` (CWE-940 safe-path prefilter) |
| `invalid oauth state` | `fixture-literal` (CWE-940 safe-path error string) |
| `SendResetLink(` / `SendResetLinkPure(` | `fixture-literal` (CWE-941 helpers) |
| `[]string{email}` | `fixture-literal` (CWE-941 recipient slice) |
| `smtp.SendMail` | `negative-gate` (CWE-941 prefilter; call_facts primary) |
| `Query("email")` / `Query().Get("email")` | `negative-gate` / co-signal (CWE-941 corpus co-presence) |
| `user.Email` / `lookupEmail(` / `sessionUserID` | `negative-gate` (CWE-941 safe-path prefilter) |

Note: bare `code` co-presence token for CWE-940 is too generic to label; left unlabeled (same class as CWE-331 bare `code`).

#### Maturity table

- `CWE-940`, `CWE-941` added to `is_fixture_only` in `src/rules/maturity.rs`.
- Structural promotion bar from §1.3 is **not** met for either rule (fixture helpers / exact SQL or recipient slice remain required for emit).

#### Canary decision — 2026-07-18

Source revision at documentation time: `4567d725deb21af1f5cda96c0262a657c5ffc885` (working tree on `chore/pending-items-2` with this tranche; release binary used for hit-count measurement). Target revisions match Tranche 1/2/3:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-940,CWE-941 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-940 ×0, CWE-941 ×0.

**Decision (2026-07-18):** quarantine CWE-940 and CWE-941 as fixture-only (`--profile all` only). Keep CWE-941 call-facts primary for `smtp.SendMail` without structural promotion. Do not delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit only when evidence is generalized beyond corpus helper names / exact SQL / recipient-slice literals (e.g. user-controlled binding into `smtp.SendMail` recipients without `SendResetLink` name gates).

#### Next long-tail candidates (not in this tranche)

- Continue NEEDLES-comment pass only within domain-sized families; do not bulk-edit the index.
- file_handling / path: CWE-434 (client filename + `/var/www/static/avatars` corpus paths).
- network_binding: CWE-1327 (`StartPublicAPI` + `:9090` bind museum).
- concurrency TOCTOU: CWE-367 (`os.Stat(target)` + `os.ReadFile(target)` exact names).
- permissions chown: CWE-648 / CWE-708 (`os.Chown` + FormValue uid/path / `owner_uid` shapes) — rewrite candidate for call_facts `os.Chown` when oracle-safe.
- Transport TLS: CWE-319 (still needle-primary).
- Remaining needle-primary long-tail without dated disposition stays under [#39](https://github.com/chinmay-sawant/codehound/issues/39).

---

## Dependencies

- `src/lang/go/detectors/cwe/source_index.rs`
- `src/rules/maturity.rs` and profile-pack tests
- CWE fixture manifest and real Go canary repositories
- The preserved scanner finding oracle for any detector rewrite

# v0.0.5 — CWE Catalog Trust Audit, Tranche 1

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2
> **Status:** Tranches 1–5 complete (merged [#41](https://github.com/chinmay-sawant/codehound/pull/41), [#43](https://github.com/chinmay-sawant/codehound/pull/43); [#39](https://github.com/chinmay-sawant/codehound/issues/39) / [#42](https://github.com/chinmay-sawant/codehound/issues/42) closed). **Long-tail under [#45](https://github.com/chinmay-sawant/codehound/issues/45)** — file-mode family recorded in §2.11 (CWE-250 keep Heuristic; CWE-252/552 fixture-only; call-facts rewrite for 552). Remaining undated CWE catalog is still not fully certified (inventory in §2.11).
> **Estimated effort:** Incremental, rule-family by rule-family under #45; do not bulk-promote or bulk-check the remaining catalog.

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

#### Next long-tail candidates → issue [#42](https://github.com/chinmay-sawant/codehound/issues/42)

Checklist plan: **`plans/v0.0.5/cwe-catalog-trust-next.md`** (branch `chore/cwe-trust-tranche5`).

- Continue NEEDLES-comment pass only within domain-sized families; do not bulk-edit the index.
- file_handling / path: CWE-434 — **§2.6** (this tranche).
- network_binding: CWE-1327 — **§2.7** (this tranche).
- concurrency TOCTOU: CWE-367 — **§2.8** (this tranche; call-facts primary, keep Heuristic).
- permissions chown: CWE-648 / CWE-708 — **§2.9** (this tranche; call-facts primary for `os.Chown`, fixture-only).
- Transport TLS + JWT neighbors: CWE-319 / CWE-358 — **§2.10** (this tranche; both fixture-only; CWE-319 call-facts primary for ListenAndServe).
- Do **not** track further work under closed [#39](https://github.com/chinmay-sawant/codehound/issues/39).

### 2.6 File/path — CWE-434

> **Domain:** `src/lang/go/detectors/cwe/domains/file_handling.rs`
> **Date:** 2026-07-18
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)
> **Scope:** Phase 1 of `cwe-catalog-trust-next.md` only. CWE-434 (client filename + `/var/www/static/avatars` corpus upload/serve shape). No detector rewrite; NEEDLES labels + maturity quarantine.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-434 | Exact co-presence of client filename field (`file.Filename` / `hdr.Filename`) + store sink (`SaveUploadedFile(file, dest)` / `os.Create(dest)`) + corpus paths (`/var/www/static/avatars` / `/static/avatars/`) + exact redirect string with client filename; negative gates `unsupported file type` / `filepath.Ext(` / `hex.EncodeToString(` | Quarantine **fixture-only**. Corpus avatar upload/serve paths and exact redirect shapes, not a generalized unrestricted-upload AST/call-fact detector. |

#### Detector shape (no rewrite)

`detect_cwe_434` remains needle-primary:

- Positive store shape: (`file.Filename` ∧ `SaveUploadedFile(file, dest)`) ∨ (`hdr.Filename` ∧ `os.Create(dest)`)
- Positive serve shape: (`/var/www/static/avatars` ∨ `/static/avatars/`) ∧ exact gin or stdlib redirect using client filename
- Negative: `unsupported file type` ∨ `filepath.Ext(` ∨ `hex.EncodeToString(` (allow-list + random stored name)
- Emit span via `source.find("file.Filename")` / `hdr.Filename`

**Why not call-facts / structural now:** `os.Create` is production-shaped, but emit still requires fixture destination name `dest`, exact avatar corpus paths, and full redirect string templates with `file.Filename` / `hdr.Filename`. A generalized unrestricted-upload detector would need user-controlled filename → store → web-serve flow evidence (multipart header binding, destination construction, public serve path) without museum path literals. §1.3 structural bar is **not** met. Call-facts primary alone would not preserve the current oracle without the corpus co-shapes.

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `/var/www/static/avatars` | `fixture-literal` (CWE-434 corpus upload path) |
| `/static/avatars/` | `fixture-literal` (CWE-434 corpus serve path prefix) |
| `SaveUploadedFile(file, dest)` | `fixture-literal` (CWE-434 gin dest shape) |
| `os.Create(dest)` | `fixture-literal` (CWE-434 pure-stdlib dest shape) |
| `file.Filename` / `hdr.Filename` | `fixture-literal` (CWE-434 client filename co-signal) |
| `c.Redirect(http.StatusFound, "/static/avatars/"+file.Filename)` | `fixture-literal` (CWE-434 gin redirect) |
| `http.Redirect(w, r, "/static/avatars/"+hdr.Filename, http.StatusFound)` | `fixture-literal` (CWE-434 pure redirect) |
| `unsupported file type` | `fixture-literal` (CWE-434 safe-path error string) |
| `filepath.Ext(` | `negative-gate` (CWE-434 extension allowlist prefilter) |
| `hex.EncodeToString(` | `negative-gate` (CWE-434 random stored-name prefilter) |

#### Maturity table

- `CWE-434` added to `is_fixture_only` in `src/rules/maturity.rs`.
- Structural promotion bar from §1.3 is **not** met (corpus paths + exact redirect / dest shapes remain required for emit).

#### Canary decision — 2026-07-18

Source revision at documentation time: `625e153bb60ee69fdfafa92c81375e9f0da2d538` (working tree on `chore/cwe-trust-tranche5` with this phase; release binary used for hit-count measurement — maturity quarantine only affects default packs, not `--profile all --only`). Target revisions match Tranche 1–4:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-434 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-434 ×0.

**Decision (2026-07-18):** quarantine CWE-434 as fixture-only (`--profile all` only). Do not rewrite detector or delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit only when evidence is generalized beyond corpus avatar paths / exact redirect templates (e.g. multipart client-filename binding into store + web-serve without museum path literals).

### 2.7 Network binding — CWE-1327

> **Domain:** `src/lang/go/detectors/cwe/domains/network_binding.rs`
> **Date:** 2026-07-18
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)
> **Scope:** Phase 2 of `cwe-catalog-trust-next.md` only. CWE-1327 (`StartPublicAPI` + `:9090` unrestricted bind museum). No detector rewrite; NEEDLES labels + maturity quarantine.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-1327 | Exact helpers `StartPublicAPI(` / `StartPublicAPIPure(` plus `Run(":9090")` / `ListenAndServe(":9090",`; negative gate `127.0.0.1:9090`; span via `source.find(":9090")` | Quarantine **fixture-only**. Project-specific public-API helper names and fixed port `:9090` corpus bind, not a generalized unrestricted-bind AST/call-fact detector. |

#### Detector shape (no rewrite)

`detect_cwe_1327` remains needle-primary:

- Positive: (`StartPublicAPI(` ∨ `StartPublicAPIPure(`) ∧ (`Run(":9090")` ∨ `ListenAndServe(":9090",`)
- Negative: `127.0.0.1:9090` (safe fixtures use loopback)
- Emit message: service binds to all interfaces instead of restricted loopback

**Why not call-facts / structural now:** A production-shaped unrestricted-bind rule would need to distinguish intentional public listens (`:80`, `:443`, configured bind addrs) from accidental all-interface exposure of admin/local services. The current oracle only matches museum helpers + port `9090`. Generalizing would either mass-FP real HTTP servers or require policy/config intent evidence outside this domain. §1.3 structural bar is **not** met.

Neighbor needles **not** relabeled here (other families own them):

- `10.20.30.40:9090` — CWE-1051 hard-coded private endpoint
- `net.Listen("tcp", ":9090")` — CWE-605 lifecycle/runtime
- bare `ListenAndServe(` / `http.ListenAndServe(` — CWE-319 / transport prefilters

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `StartPublicAPI(` / `StartPublicAPIPure(` | `fixture-literal` (CWE-1327 helpers) |
| `Run(":9090")` | `fixture-literal` (CWE-1327 gin bind) |
| `ListenAndServe(":9090",` | `fixture-literal` (CWE-1327 pure bind) |
| `127.0.0.1:9090` | `negative-gate` (CWE-1327 safe-path prefilter) |

#### Maturity table

- `CWE-1327` added to `is_fixture_only` in `src/rules/maturity.rs`.
- Structural promotion bar from §1.3 is **not** met (fixture helpers + fixed `:9090` remain required for emit).

#### Canary decision — 2026-07-18

Source revision at documentation time: `625e153bb60ee69fdfafa92c81375e9f0da2d538` (working tree on `chore/cwe-trust-tranche5` with this phase; release binary used for hit-count measurement — maturity quarantine only affects default packs, not `--profile all --only`). Target revisions match Tranche 1–4:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-1327 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-1327 ×0.

**Decision (2026-07-18):** quarantine CWE-1327 as fixture-only (`--profile all` only). Do not rewrite detector or delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit only when evidence is generalized beyond corpus helper names / fixed `:9090` (e.g. bind-address classification with policy-aware public-vs-loopback distinction that does not mass-FP intentional public servers).

### 2.8 TOCTOU — CWE-367

> **Domain:** `src/lang/go/detectors/cwe/domains/concurrency/toctou.rs`
> **Date:** 2026-07-18
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)
> **Scope:** Phase 3 of `cwe-catalog-trust-next.md` only. Concurrency TOCTOU long-tail previously needle-primary on exact `os.Stat(target)` / `os.ReadFile(target)` corpus text. Call-facts primary rewrite recorded here; maturity remains **Heuristic** (not fixture-only, not structural-promoted).

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-367 | After rewrite: `call_facts` primary for callees `os.Stat` + `os.ReadFile` sharing the same first-arg path text; SI `os.Stat(` / `os.ReadFile` are impossibility prefilters only | Keep **Heuristic**. Production-shaped stdlib APIs + shared-path co-use; one reviewed example-path canary hit. **Not** structural-promoted (§1.3 still wants broader production actionability / negatives beyond this co-presence shape). Exact `(target)` needles are no longer emit evidence. |

#### Call-facts rewrite — CWE-367

**Rule:** `detect_cwe_367` in `concurrency/toctou.rs`.

**Before:** Needle-primary emit on exact SourceIndex substrings `os.Stat(target)` **and** `os.ReadFile(target)`; span via `source.find("os.Stat(target)")`.

**After:** Primary match requires both `os.Stat` and `os.ReadFile` in `facts.call_facts` with equal first-argument text (shared path expression). SourceIndex is retained only as:
- cheap impossibility prefilter: `os.Stat(`, `os.ReadFile`
- unused corpus literals left labeled (not required for emit): `os.Stat(target)`, `os.ReadFile(target)`

Finding span uses the matching `os.Stat` call’s `start_byte` from call facts (check site).

**Oracle:** Existing CWE-367 vulnerable fixtures still fire (`target` shared path); safe fixtures still silence (ReadFile without Stat). Neighbor fixtures with only Stat or only ReadFile must not newly fire. No fixture renames. Maturity stays **Heuristic** (stdlib co-use is production-shaped; not fixture-helper-name gated).

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `os.Stat(` | `negative-gate` (CWE-367 prefilter; call_facts primary) — **added** |
| `os.ReadFile` | `negative-gate` (CWE-367 prefilter; call_facts primary) |
| `os.Stat(target)` | `fixture-literal` (exact corpus path arg; not required for emit) |
| `os.ReadFile(target)` | `fixture-literal` (exact corpus path arg; not required for emit) |

Note: `os.ReadFile(lockPath)` remains unlabeled under this family (CWE-412 lock-path shape; out of Phase 3 scope).

#### Maturity table

- No change: `CWE-367` is **not** added to `is_fixture_only` (remains default **Heuristic**).
- Structural promotion bar from §1.3 is **not** met (shared Stat+ReadFile text is a coarse TOCTOU prefilter without control-flow ordering, symlink policy, or user-controlled-path binding).

#### Canary decision — 2026-07-18

Source revision at documentation time: working tree on `chore/cwe-trust-tranche5` (base `625e153bb60ee69fdfafa92c81375e9f0da2d538` + this Phase 3 rewrite). Release binary used for hit-count measurement. Target revisions match prior tranches:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 1 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-367 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-367 ×1.

**Reviewed hit:** `gopdfsuit/sampledata/gopdflib/load_from_json/main.go:26` — `os.Stat(jsonPath)` then `os.ReadFile(jsonPath)` in example sampledata (finding tagged `example`). Shape matches the generalized detector; not production-library noise. Would **not** have fired under the prior exact `(target)` needles.

**Decision (2026-07-18):** keep CWE-367 as **Heuristic** without structural promotion. Retain call-facts primary for shared-path `os.Stat` + `os.ReadFile`. Do not quarantine as fixture-only (emit no longer depends on corpus identifier `target`). Do not delete labeled needles solely for this canary. Revisit structural promotion only when evidence adds ordering / path-taint / safer-alternative negatives beyond co-presence of Stat and ReadFile on the same argument text.

### 2.9 Permissions — CWE-648 / CWE-708

> **Domain:** `src/lang/go/detectors/cwe/domains/general_security/permissions_and_ownership/chown.rs`
> **Date:** 2026-07-18
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)
> **Scope:** Phase 4 of `cwe-catalog-trust-next.md` only. Permissions chown / ownership long-tail previously needle-primary on `os.Chown(` + exact FormValue/PostForm form keys / `owner_uid`. Call-facts primary rewrite for `os.Chown` recorded here; both rules maturity-quarantined as fixture-only.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-648 | After rewrite: `call_facts` primary for callee `os.Chown`; SI still requires `uid` + `FormValue("uid")`/`PostForm("uid")` + `FormValue("path")`/`PostForm("path")` without `uploadRoot` / `spoolDir` / `serviceUID` / `Setuid(` | Quarantine **fixture-only**. Stdlib chown sink is production-shaped and call-facts primary, but emit still depends on exact form-key corpus co-signals. **Not** structural-promoted (§1.3 bar not met). |
| CWE-708 | After rewrite: `call_facts` primary for callee `os.Chown`; SI still requires `owner_uid` + `FormValue("dest")`/`PostForm("dest")` without `spoolDir` / `serviceUID` / `serviceGID` | Quarantine **fixture-only**. Same chown sink proof, but emit still depends on `owner_uid` identifier + exact dest form key. **Not** structural-promoted (§1.3 bar not met). |

#### Call-facts rewrite — CWE-648 / CWE-708

**Rules:** `detect_cwe_648` and `detect_cwe_708` in `chown.rs`.

**Before:** Needle-primary emit on SourceIndex `os.Chown(` plus form-key / `owner_uid` co-presence; span via `source.find("os.Chown(")` (648) or `source.find("owner_uid")` (708).

**After:** Primary match iterates `facts.call_facts` for callee `os.Chown`. SourceIndex is retained as:
- cheap impossibility prefilter: `os.Chown(`
- corpus co-signals (oracle):
  - CWE-648: `uid` + `FormValue("uid")`/`PostForm("uid")` + `FormValue("path")`/`PostForm("path")`
  - CWE-708: `owner_uid` + `FormValue("dest")`/`PostForm("dest")`
- negative prefilters:
  - CWE-648: `uploadRoot` / `spoolDir` / `serviceUID` / `Setuid(`
  - CWE-708: `spoolDir` / `serviceUID` / `serviceGID`

Finding span uses `chown_call.start_byte` from call facts for both rules.

**Oracle:** Existing CWE-648 / CWE-708 vulnerable fixtures still fire; safe fixtures still silence (upload-root / service-uid / spool-dir negatives). Neighbor fixtures that use `os.Chown` without the form-key / `owner_uid` co-shape must not newly fire. No fixture renames. Maturity is **fixture-only** (not Heuristic — form keys / `owner_uid` dominate).

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `os.Chown(` | `negative-gate` (CWE-648 / CWE-708 prefilter; call_facts primary) |
| `FormValue("uid")` / `PostForm("uid")` | `fixture-literal` / co-signal (CWE-648 corpus) |
| `FormValue("path")` / `PostForm("path")` | `fixture-literal` / co-signal (CWE-648 corpus) |
| `FormValue("dest")` / `PostForm("dest")` | `fixture-literal` / co-signal (CWE-708 corpus) |
| `owner_uid` | `fixture-literal` (CWE-708 client-chosen owner identifier) |
| `uploadRoot` | `negative-gate` (CWE-648 safe-path prefilter) |
| `spoolDir` | `negative-gate` (CWE-648 / CWE-708 safe-path prefilter) |
| `serviceUID` / `serviceGID` | `negative-gate` (CWE-648 / CWE-708 safe-path prefilter) |
| `Setuid(` | `negative-gate` (CWE-648 safe-path prefilter; also CWE-272 shape) |

Note: bare `uid` co-presence token for CWE-648 is too generic to label; left unlabeled (same class as CWE-331 / CWE-940 bare `code`).

#### Maturity table

- `CWE-648`, `CWE-708` added to `is_fixture_only` in `src/rules/maturity.rs`.
- Structural promotion bar from §1.3 is **not** met for either rule (exact form keys / `owner_uid` remain required for emit).

#### Canary decision — 2026-07-18

Source revision at documentation time: working tree on `chore/cwe-trust-tranche5` (base `625e153bb60ee69fdfafa92c81375e9f0da2d538` + this Phase 4 rewrite). Release binary used for hit-count measurement — maturity quarantine only affects default packs, not `--profile all --only`. Target revisions match prior tranches:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-648,CWE-708 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-648 ×0, CWE-708 ×0.

**Decision (2026-07-18):** quarantine CWE-648 and CWE-708 as fixture-only (`--profile all` only). Keep call-facts primary for `os.Chown` without structural promotion. Do not delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit only when evidence is generalized beyond exact form keys / `owner_uid` (e.g. user-controlled path + uid bindings into `os.Chown` without museum form-field names).

### 2.10 Transport TLS + JWT — CWE-319 / CWE-358

> **Domains:** `src/lang/go/detectors/cwe/domains/information_exposure/secrets_and_transport/transport.rs` (319); `src/lang/go/detectors/cwe/domains/general_security/identity_and_authentication/jwt.rs` (358)
> **Date:** 2026-07-18
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)
> **Scope:** Phase 5 of `cwe-catalog-trust-next.md` only. CWE-319 (card PAN/CVV over cleartext `ListenAndServe`) and CWE-358 (Bearer JWT decode without structure/algorithm checks). Neighbor CWE-347 (JWT without signature verify) was already quarantined fixture-only in §2.4; no other JWT-neighbor rules remain undated in this family.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-319 | After rewrite: `call_facts` primary for callee ending in `ListenAndServe` (not `ListenAndServeTLS`); SI still requires `CVV` + `Number` card-field co-signals; SI negatives `ListenAndServeTLS(` / `tls.Config` | Quarantine **fixture-only**. Stdlib cleartext listen is production-shaped and call-facts primary, but emit still depends on corpus payment field names (`CVV` / `Number`). **Not** structural-promoted (§1.3 bar not met). |
| CWE-358 | Exact `strings.TrimPrefix(raw, "Bearer ")` + `DecodeString(parts[1])` + `json.Unmarshal(payload, &claims)` without `invalid jwt structure` / `unsupported jwt algorithm` | Quarantine **fixture-only**. Same JWT corpus variable shape as CWE-347 (`raw` / `parts` / `payload` / `claims`) plus exact safe-path error strings; not a generalized JWT-structure/alg AST/call-fact detector. |

#### Call-facts rewrite — CWE-319

**Rule:** `detect_cwe_319` in `transport.rs`.

**Before:** Needle-primary emit on `CVV` + `Number` + `ListenAndServe(` / `http.ListenAndServe(` without `ListenAndServeTLS(` / `tls.Config`; span via `source.find("ListenAndServe")`.

**After:** Primary match iterates `facts.call_facts` for a callee ending with `ListenAndServe` and not `ListenAndServeTLS`. SourceIndex is retained as:
- cheap impossibility prefilter: `ListenAndServe(` / `http.ListenAndServe(` / `http.ListenAndServe`
- corpus co-signals (oracle): `CVV` + `Number`
- negative prefilters: `ListenAndServeTLS(` / `tls.Config`

Finding span uses `listen_call.start_byte` from call facts.

**Oracle:** Existing CWE-319 vulnerable fixtures still fire (`http.ListenAndServe` + card payload); safe fixtures still silence (`tls.Config` + `ListenAndServeTLS`). Neighbor plain-HTTP listeners without `CVV`+`Number` must not newly fire. No fixture renames. Maturity is **fixture-only** (payment field names dominate).

**Why not structural / Heuristic keep:** Without the card-field museum gate, every cleartext HTTP server would be a candidate finding. A generalized cleartext-sensitive-transport rule needs sensitive-data classification (or taint of card/PII into the served handler) beyond exact `CVV`/`Number` identifiers. §1.3 bar is **not** met.

#### CWE-358 — no rewrite

`detect_cwe_358` remains needle-primary (same class as CWE-347 §2.4):

- Positive: `strings.TrimPrefix(raw, "Bearer ")` ∧ `DecodeString(parts[1])` ∧ `json.Unmarshal(payload, &claims)`
- Negative: `invalid jwt structure` ∨ `unsupported jwt algorithm`
- Emit span via `source.find("DecodeString(parts[1])")`

**Why not call-facts:** There is no single stdlib callee that is both necessary and sufficient. `json.Unmarshal` / `DecodeString` are shared sinks used widely; emit depends on exact fixture variable names and Bearer-trim text. Call-facts primary would not remove corpus coupling and would risk neighbor noise. Defer any rewrite until a generalized JWT parse/verify fact model exists.

**JWT neighbor note:** CWE-347 (manual split/decode without `VerifyPKCS1v15`) already fixture-only under §2.4. No additional JWT-neighbor detector remains undated under Phase 5.

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `CVV` / `Number` | `fixture-literal` (CWE-319 payment field co-signals) |
| `ListenAndServe(` / `http.ListenAndServe` / `http.ListenAndServe(` | `negative-gate` (CWE-319 prefilter; call_facts primary after §2.10) |
| `ListenAndServeTLS(` / `tls.Config` | `negative-gate` (CWE-319 safe-path prefilter) |
| `strings.TrimPrefix(raw, "Bearer ")` | `fixture-literal` (CWE-358 Bearer corpus shape) |
| `DecodeString(parts[1])` / `json.Unmarshal(payload, &claims)` / `strings.Split(raw, ".")` | already `fixture-literal` from §2.4 (CWE-347 / CWE-358 JWT corpus) |
| `invalid jwt structure` / `unsupported jwt algorithm` | `fixture-literal` (CWE-358 safe-path error strings) |

Neighbor needle **not** relabeled here (other families own it):

- `ListenAndServe(":9090",` — CWE-1327 pure bind corpus (§2.7)

#### Maturity table

- `CWE-319`, `CWE-358` added to `is_fixture_only` in `src/rules/maturity.rs`.
- Structural promotion bar from §1.3 is **not** met for either rule (payment field names / JWT variable names + exact error strings remain required for emit).

#### Canary decision — 2026-07-18

Source revision at documentation time: working tree on `chore/cwe-trust-tranche5` (base `625e153bb60ee69fdfafa92c81375e9f0da2d538` + this Phase 5 rewrite/quarantine). Release binary used for hit-count measurement — maturity quarantine only affects default packs, not `--profile all --only`. Target revisions match prior tranches:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-319,CWE-358 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-319 ×0, CWE-358 ×0.

**Decision (2026-07-18):** quarantine CWE-319 and CWE-358 as fixture-only (`--profile all` only). Keep CWE-319 call-facts primary for `ListenAndServe` without structural promotion. Do not rewrite CWE-358. Do not delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit CWE-319 only when sensitive-data classification generalizes beyond `CVV`/`Number`; revisit CWE-358 only when JWT structure/alg checks are modeled without exact variable names / error-string museum gates.

### 2.11 File-mode permissions long-tail — CWE-250 / CWE-252 / CWE-552

> **Domain:** `src/lang/go/detectors/cwe/domains/general_security/permissions_and_ownership/file_modes.rs`
> **Date:** 2026-07-19
> **Issue:** [#45](https://github.com/chinmay-sawant/codehound/issues/45)
> **Scope:** First long-tail domain under #45 after tranche 5. High-signal stdlib file-mode shapes (`os.WriteFile` / `os.Chmod`) not already dispositioned in §§2.1–2.10. Checklist: `plans/v0.0.5/cwe-catalog-trust-45.md`.

#### Inventory note (undated residual)

Non-taint domain detectors without a dated disposition after this section remain large (~140 rules across access_control, credentials, concurrency, configuration, injection neighbors, etc.). This tranche deliberately audits **one domain-sized family only**. Prefer next batches:

- Access-control file permissions siblings: CWE-276 / 277 / 278 / 279 / 281 / 921 (`access_control/file_permissions/file_modes.rs` — many already call-facts primary)
- Password-storage hashing: CWE-256 / 257 / 261 / 916 (`credentials_and_secrets/password_storage/hashing.rs` — CWE-916 is `md5.Sum` + password co-signal)
- Transport neighbors: CWE-524 / 538 (token cache / public secret export museum)
- Deserialization: CWE-502 (`gob.NewDecoder` + adminAction corpus)

Do **not** bulk-label NEEDLES or bulk-quarantine from this inventory alone.

#### Audited dispositions

| Rule | Current detector evidence | Disposition |
|---|---|---|
| CWE-250 | After light SI prefilter: `call_facts` primary for callee `os.WriteFile` with third arg exact `0o777`; SI `os.WriteFile(` impossibility prefilter only | Keep **Heuristic**. Production-shaped world-writable WriteFile mode. **Not** structural-promoted (§1.3 still wants broader mode classification / real-module evidence beyond zero-hit canary). |
| CWE-252 | `call_facts` primary for `os.WriteFile` whose args contain exact `/var/log/audit.log` or `/var/log/journal.log`; SI negative `if err := os.WriteFile(` | Quarantine **fixture-only**. Unchecked-write smell is real, but emit is gated on corpus log path literals (would mass-FP general unchecked writes without them). **Not** structural-promoted. |
| CWE-552 | After rewrite: `call_facts` primary for callee `os.Chmod` with mode `0o777`; SI still requires `FormFile("contract")` + `/srv/contracts` without `filepath.Base(` / `os.Chmod(dest, 0o600)` | Quarantine **fixture-only**. Stdlib chmod sink is production-shaped and call-facts primary, but emit still depends on contract-upload corpus co-signals. **Not** structural-promoted. |

#### Call-facts rewrite — CWE-552

**Rule:** `detect_cwe_552` in `file_modes.rs`.

**Before:** Needle-primary emit on `FormFile("contract")` + `/srv/contracts` + `os.Chmod(dest, 0o777)` without `filepath.Base(` / `os.Chmod(dest, 0o600)`; span via `source.find("os.Chmod(dest, 0o777)")`.

**After:** Primary match iterates `facts.call_facts` for callee `os.Chmod` with second argument exact `0o777`. SourceIndex is retained as:
- cheap impossibility prefilter: `os.Chmod(dest, 0o777)`
- corpus co-signals (oracle): `FormFile("contract")`, `/srv/contracts`
- negative prefilters: `filepath.Base(`, `os.Chmod(dest, 0o600)`

Finding span uses `chmod_call.start_byte` from call facts.

**Oracle:** Existing CWE-552 vulnerable fixtures still fire (gin + pure stdlib); safe fixtures still silence (Base + 0o600). Neighbor fixtures that use `os.Chmod` without the contract-upload co-shape must not newly fire. No fixture renames. Maturity is **fixture-only** (corpus form field + path dominate).

#### CWE-250 / CWE-252 — no structural change beyond prefilter hygiene

- **CWE-250:** Already call-facts primary for `os.WriteFile` + `0o777`. Added SI `os.WriteFile(` impossibility prefilter only (oracle-neutral). Remains **Heuristic**.
- **CWE-252:** Already call-facts primary for `os.WriteFile` + audit/journal path args; SI negative for error-checked form. No rewrite needed; maturity quarantine to fixture-only because path co-signals are museum.

#### NEEDLES comment pass (this family)

Labeled in `src/lang/go/detectors/cwe/source_index.rs` (no bulk deletes):

| Needle | Label |
|---|---|
| `os.WriteFile(` | `negative-gate` (CWE-250 / CWE-252 prefilter; call_facts primary) |
| `if err := os.WriteFile(` | `fixture-literal` (CWE-252 safe-path error-checked form) |
| `FormFile("contract")` | `fixture-literal` (CWE-552 corpus form field) |
| `/srv/contracts` | `fixture-literal` (CWE-552 corpus store path) |
| `os.Chmod(dest, 0o777)` | `fixture-literal` (CWE-552 corpus chmod; call_facts primary after §2.11) |
| `os.Chmod(dest, 0o600)` | `negative-gate` (CWE-552 safe-path owner-only mode) |
| `filepath.Base(` | `negative-gate` (CWE-552 / path basename sanitization prefilter) |

Note: exact log path strings `/var/log/audit.log` / `/var/log/journal.log` are matched via call-fact argument text, not as top-level NEEDLES entries (left unlabeled in the index).

Neighbor needles **not** relabeled here (other families own them):

- Access-control file-mode modes `0666` / `0777` / `MkdirAll(dir, 0777)` — CWE-276/277/279 siblings (next-candidate inventory)
- `os.Chown(` — already §2.9

#### Maturity table

- `CWE-252`, `CWE-552` added to `is_fixture_only` in `src/rules/maturity.rs`.
- `CWE-250` remains default **Heuristic** (not on the structural allow-list).
- Structural promotion bar from §1.3 is **not** met for any rule in this family.

#### Canary decision — 2026-07-19

Source revision at documentation time: working tree on `chore/cwe-trust-longtail-45`. Release binary used for hit-count measurement — maturity quarantine only affects default packs, not `--profile all --only`. Target revisions match prior tranches:

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

```sh
target/release/codehound TARGET --profile all \
  --only CWE-250,CWE-252,CWE-552 \
  --format json --json-envelope --no-fail --no-cache
```

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-250 ×0, CWE-252 ×0, CWE-552 ×0.

**Decision (2026-07-19):** keep CWE-250 as **Heuristic** without structural promotion (zero-hit canary is not sufficient for delete or structural promotion). Quarantine CWE-252 and CWE-552 as fixture-only (`--profile all` only). Keep CWE-552 call-facts primary for `os.Chmod` without structural promotion. Do not delete needles solely for this zero-hit canary; retain fixture coverage as regression evidence. Revisit CWE-250 only when real-module hits or broader mode taxonomy meet §1.3; revisit 252/552 only when path/form co-signals generalize beyond corpus literals.

---

## Dependencies

- `src/lang/go/detectors/cwe/source_index.rs`
- `src/rules/maturity.rs` and profile-pack tests
- CWE fixture manifest and real Go canary repositories
- The preserved scanner finding oracle for any detector rewrite


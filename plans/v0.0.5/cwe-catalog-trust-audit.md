# v0.0.5 — CWE Catalog Trust Audit, Tranche 1

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2
> **Status:** Tranche 1 complete (PRNG + CWE-798 quarantined). Tranche 2 complete (cipher misuse: CWE-1204/1240 fixture-only; CWE-325 stays Heuristic). Further long-tail NEEDLES audit and maturity expansion remain under GitHub issue [#39](https://github.com/chinmay-sawant/codehound/issues/39). The remaining CWE catalog is not yet certified.
> **Estimated effort:** Incremental, rule-family by rule-family; do not bulk-promote or bulk-check the remaining catalog.

---

## Overview

This audit keeps the Go CWE catalog honest. It separates rules that can support ordinary CI use from exact corpus patterns that remain useful only under `--profile all`.

---

## Executive Summary

The first tranche confirms that CWE-334, CWE-335, CWE-338, CWE-342, CWE-343, and CWE-798 must remain `fixture-only`. Their current implementations depend on exact numeric bounds, identifier names, formulas, or a literal DSN rather than generalized call/type/flow evidence. They are already excluded from recommended and security profiles; this audit records why and adds an explicit promotion bar for future structural rules.

Tranche 2 extends the same bar to the cipher-misuse family: CWE-1204 and CWE-1240 are corpus-literal detectors and are now `fixture-only`; CWE-325 is a production-shaped stdlib API smell kept as **Heuristic** without structural promotion (needle-primary emit). A zero-hit real-module canary (0/126 files) supports keep/quarantine rather than delete.

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

- [x] Select one long-tail detector whose call facts already provide a complete primary signal, then replace its primary `SourceIndex.has` logic without changing its finding oracle. **Done for CWE-918** (see §2.1); further rewrites stay issue-gated under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Retain only API/stdlib needles that can cheaply prove a detector impossible; label fixture-only corpus literals in the source index as they are audited. **Tranche 2 cipher family labeled** (see §2.2); remaining NEEDLES pass continues incrementally under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Record a canary hit-rate and a dated keep/narrow/quarantine/delete decision for each completed family; Tranche 1 PRNG family (§1.2) and Tranche 2 cipher family (§2.2) are recorded. Further families remain under [#39](https://github.com/chinmay-sawant/codehound/issues/39).

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
| CWE-325 | `cipher.NewCTR(` + `XORKeyStream(` without `cipher.NewGCM(` / `Seal(` | Keep **Heuristic**. Stdlib API tokens are production-shaped negative-gate/prefilter needles, but emission is still needle-primary (no call-fact/AST primary). **Not promoted** to structural. |
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

- Crypto-strength siblings: CWE-323 (fixed nonce identifiers), CWE-328 (`md5.Sum` API — likely keep Heuristic), CWE-331 (`Intn(900000)+100000` fixture bound).
- JWT: CWE-347 (manual split/decode without verify — needle-primary).
- Continue NEEDLES-comment pass only within domain-sized families; do not bulk-edit the index.

---

## Dependencies

- `src/lang/go/detectors/cwe/source_index.rs`
- `src/rules/maturity.rs` and profile-pack tests
- CWE fixture manifest and real Go canary repositories
- The preserved scanner finding oracle for any detector rewrite

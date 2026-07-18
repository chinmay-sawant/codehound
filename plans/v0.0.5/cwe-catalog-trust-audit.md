# v0.0.5 — CWE Catalog Trust Audit, Tranche 1

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2
> **Status:** In progress. The known fixture-shaped long-tail rules are audited and quarantined; the remaining CWE catalog is not yet certified.
> **Estimated effort:** Incremental, rule-family by rule-family; do not bulk-promote or bulk-check the remaining catalog.

---

## Overview

This audit keeps the Go CWE catalog honest. It separates rules that can support ordinary CI use from exact corpus patterns that remain useful only under `--profile all`.

---

## Executive Summary

The first tranche confirms that CWE-334, CWE-335, CWE-338, CWE-342, CWE-343, and CWE-798 must remain `fixture-only`. Their current implementations depend on exact numeric bounds, identifier names, formulas, or a literal DSN rather than generalized call/type/flow evidence. They are already excluded from recommended and security profiles; this audit records why and adds an explicit promotion bar for future structural rules.

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
- [ ] Audit the remaining long-tail rules in domain-sized tranches; create an explicit disposition for every rule changed or promoted.

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

- [ ] Select one long-tail detector whose call facts already provide a complete primary signal, then replace its primary `SourceIndex.has` logic without changing its finding oracle.
- [ ] Retain only API/stdlib needles that can cheaply prove a detector impossible; label fixture-only corpus literals in the source index as they are audited.
- [ ] Record a canary hit-rate and a dated keep/narrow/quarantine/delete decision for each completed family; the first fixture-only family is recorded above.

---

## Dependencies

- `src/lang/go/detectors/cwe/source_index.rs`
- `src/rules/maturity.rs` and profile-pack tests
- CWE fixture manifest and real Go canary repositories
- The preserved scanner finding oracle for any detector rewrite

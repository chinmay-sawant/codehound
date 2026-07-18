# v0.0.5 — CWE Catalog Trust (long-tail under #45)

> **Parent:** `plans/v0.0.5/cwe-catalog-trust-audit.md` (promotion bar §1.3; history §§1–2.10)  
> **Issue:** [#45](https://github.com/chinmay-sawant/codehound/issues/45)  
> **Branch:** `chore/cwe-trust-longtail-45`  
> **Status:** Domain audit executed — file-mode family CWE-250/252/552 (§2.11).  

> **Continues from:** closed [#42](https://github.com/chinmay-sawant/codehound/issues/42); merged [#43](https://github.com/chinmay-sawant/codehound/pull/43)

---

## Overview

Domain-sized CWE honesty work only. Do **not** bulk-promote or bulk-delete. Prefer:

1. NEEDLES labels (`negative-gate` / `fixture-literal`)
2. Maturity disposition (Heuristic keep vs fixture-only)
3. Call-facts primary rewrite when oracle-safe
4. Dated canary on gopdfsuit / monsoon / go-retry

Canary command shape:

```sh
target/release/codehound TARGET --profile all \
  --only CWE-A,CWE-B,CWE-C \
  --format json --json-envelope --no-fail --no-cache
```

---

## Phase 0: Process gate

- [x] Branch `chore/cwe-trust-longtail-45` from `origin/master`
- [x] Inventory undated residual (see audit §2.11 inventory note)
- [x] Checklist plan exists (`plans/v0.0.5/cwe-catalog-trust-45.md`)

---

## Phase 1: File-mode permissions family

**Rules:** CWE-250, CWE-252, CWE-552  
**Domain:** `src/lang/go/detectors/cwe/domains/general_security/permissions_and_ownership/file_modes.rs`

- [x] Read detectors + fixtures (stdlib + frameworks)
- [x] NEEDLES labels for this family only
- [x] Call-facts rewrite for CWE-552 (`os.Chmod` + `0o777`); SI prefilter hygiene for CWE-250/252
- [x] Disposition: CWE-250 keep Heuristic; CWE-252/552 fixture-only quarantine
- [x] Update `maturity.rs` (`CWE-252`, `CWE-552` → `is_fixture_only`)
- [x] Canary: `--only CWE-250,CWE-252,CWE-552` on gopdfsuit / monsoon / go-retry
- [x] Append audit section (§2.11) to `cwe-catalog-trust-audit.md`
- [x] Preserve fixture oracle; base fixtures kept; no named variants required

---

## Phase 2: Validation + ship prep

- [x] `cargo test --locked --test go_cwe_detector_fixtures`
- [x] `make lint`
- [x] `make test` (if time)
- [x] Commit + push branch
- [x] Comment on #45 (COMMENT_TEMPLATE tone)
- [ ] PR opened by parent epic orchestrator (out of scope for this agent)

---

## Out of scope (do not implement under this batch)

- BP-66..165 detectors
- Taint / typed Go / Python
- Bulk CWE index rewrite or bulk maturity flip
- Access-control file-mode siblings (276/277/278/…) — inventory only; future issue batch
- Opening a PR (parent will)

---

## Dependencies

- Release binary + canary paths (`gopdfsuit`, `real-repos/monsoon`, `real-repos/go-retry`)
- `src/lang/go/detectors/cwe/**`, `src/rules/maturity.rs`
- Fixture oracle: `cargo test --locked --test go_cwe_detector_fixtures`

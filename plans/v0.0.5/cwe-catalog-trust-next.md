# v0.0.5 — CWE Catalog Trust (next batch)

> **Parent:** `plans/v0.0.5/cwe-catalog-trust-audit.md` (promotion bar §1.3; history §§1–2.5)  
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)  
> **Branch:** `chore/cwe-trust-tranche5`  
> **Status:** Ready to execute — checklist open  
> **Continues from:** closed [#39](https://github.com/chinmay-sawant/codehound/issues/39); merged [#38](https://github.com/chinmay-sawant/codehound/pull/38), [#41](https://github.com/chinmay-sawant/codehound/pull/41)

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
  --only CWE-A,CWE-B \
  --format json --json-envelope --no-fail --no-cache
```

---

## Phase 0: Process gate

- [x] Create GitHub issue with assignee + labels ([#42](https://github.com/chinmay-sawant/codehound/issues/42))
- [x] Create local branch `chore/cwe-trust-tranche5`
- [x] Checklist plan exists (`plans/v0.0.5/cwe-catalog-trust-next.md`)
- [x] Issue creation guide stored next to PR template (`plans/PR/ISSUE_TEMPLATE.md`)
- [x] Link this plan from `cwe-catalog-trust-audit.md` status / next-candidates
- [x] Setup committed and pushed on `chore/cwe-trust-tranche5`

---

## Phase 1: File / path

**Rules:** CWE-434 (and tightly related path upload shapes if discovered in the same detectors file)

- [ ] Read detector + fixtures for CWE-434 (`file_handling` / path domain)
- [ ] Label family NEEDLES (`fixture-literal` vs `negative-gate`)
- [ ] Disposition: Heuristic | fixture-only | structural (only if §1.3 bar met)
- [ ] Update `maturity.rs` only if quarantining
- [ ] Canary: `--only CWE-434` on gopdfsuit, monsoon, go-retry — record hits
- [ ] Append audit section (e.g. §2.6) to `cwe-catalog-trust-audit.md`
- [ ] Preserve fixture oracle; base fixtures kept; named variants if new boundaries

---

## Phase 2: Network binding

**Rules:** CWE-1327

- [ ] Read detector + fixtures
- [ ] NEEDLES labels for bind/public-API corpus shapes
- [ ] Disposition + maturity if needed
- [ ] Canary `--only CWE-1327` — record hits
- [ ] Document in audit plan

---

## Phase 3: Concurrency TOCTOU

**Rules:** CWE-367

- [ ] Read detector + fixtures (`os.Stat` / `os.ReadFile` shapes)
- [ ] Evaluate call-facts primary for `os.Stat` / `os.ReadFile` if oracle-safe
- [ ] NEEDLES labels
- [ ] Disposition + maturity if needed
- [ ] Canary `--only CWE-367` — record hits
- [ ] Document in audit plan

---

## Phase 4: Permissions (chown / ownership)

**Rules:** CWE-648, CWE-708

- [ ] Read detectors + fixtures
- [ ] Prefer call-facts primary for `os.Chown` when oracle-safe
- [ ] NEEDLES labels for FormValue / `owner_uid` corpus shapes
- [ ] Disposition + maturity if needed
- [ ] Canary `--only CWE-648,CWE-708` — record hits
- [ ] Document in audit plan

---

## Phase 5: Transport TLS + JWT neighbors

**Rules:** CWE-319; CWE-358 (and document any other JWT neighbor still undated)

- [ ] CWE-319: needle-primary review → disposition + optional call-facts
- [ ] CWE-358: dated disposition (likely fixture-only if corpus-shaped like CWE-347)
- [ ] NEEDLES labels for this family only
- [ ] Canary for the chosen rule set — record hits
- [ ] Document in audit plan

---

## Phase 6: Call-facts opportunity pass

Across Phases 1–5 (or remaining long-tail in the same files):

- [ ] Inventory `SourceIndex.has` primary emits that map to stdlib callees already in `call_facts`
- [ ] Rewrite **at least one** additional rule **or** document why none of the scoped rules were safe
- [ ] CWE fixtures green after each rewrite
- [ ] `make lint` + `make test` (or focused CWE + maturity tests) before PR

---

## Phase 7: Ship

- [ ] Update `cwe-catalog-trust-audit.md` status line (tranche 5+ complete)
- [ ] PR body from `plans/PR/PR_TEMPLATE.md` with `--assignee @me`, labels, `Closes #42`
- [ ] Save PR record under `plans/PR/pr-cwe-trust-tranche5.md` (or `plans/v0.0.5/`)
- [ ] Author approval to commit / push / open PR

---

## Out of scope (do not implement under #42)

- BP-66..165 detectors
- Engine shared-fact reuse / flamegraph unless measured under a new issue
- Advanced taint / `--typed` / Python
- Bulk CWE index rewrite or bulk maturity flip

---

## Dependencies

- Release binary + `real-repos/{gopdfsuit,monsoon,go-retry}` (or documented paths)
- `src/lang/go/detectors/cwe/**`, `src/rules/maturity.rs`
- Fixture oracle: `cargo test --locked --test go_cwe_detector_fixtures`

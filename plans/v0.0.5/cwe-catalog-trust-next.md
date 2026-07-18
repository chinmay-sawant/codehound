# v0.0.5 — CWE Catalog Trust (next batch)

> **Parent:** `plans/v0.0.5/cwe-catalog-trust-audit.md` (promotion bar §1.3; history §§1–2.5)  
> **Issue:** [#42](https://github.com/chinmay-sawant/codehound/issues/42)  
> **Branch:** `chore/cwe-trust-tranche5`  
> **Status:** Phases 1–5 executed in parallel; call-facts rewrites landed for CWE-367/648/708/319; fixture-only quarantine for corpus families. Ready for author review / ship.  

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

- [x] Read detector + fixtures for CWE-434 (`file_handling` / path domain)
- [x] Label family NEEDLES (`fixture-literal` vs `negative-gate`)
- [x] Disposition: fixture-only quarantine (§1.3 structural bar not met; no call-facts rewrite)
- [x] Update `maturity.rs` only if quarantining (`CWE-434` → `is_fixture_only`)
- [x] Canary: `--only CWE-434` on gopdfsuit, monsoon, go-retry — record hits (0/126)
- [x] Append audit section (§2.6) to `cwe-catalog-trust-audit.md`
- [x] Preserve fixture oracle; base fixtures kept; named variants if new boundaries

---

## Phase 2: Network binding

**Rules:** CWE-1327

- [x] Read detector + fixtures
- [x] NEEDLES labels for bind/public-API corpus shapes
- [x] Disposition + maturity if needed (fixture-only quarantine)
- [x] Canary `--only CWE-1327` — record hits (0/126 across gopdfsuit/monsoon/go-retry)
- [x] Document in audit plan (`cwe-catalog-trust-audit.md` §2.7)

---

## Phase 3: Concurrency TOCTOU

**Rules:** CWE-367

- [x] Read detector + fixtures (`os.Stat` / `os.ReadFile` shapes)
- [x] Evaluate call-facts primary for `os.Stat` / `os.ReadFile` if oracle-safe
- [x] NEEDLES labels
- [x] Disposition + maturity if needed (keep Heuristic; no maturity quarantine)
- [x] Canary `--only CWE-367` — record hits (1 example-path on gopdfsuit; 0 monsoon; 0 go-retry)
- [x] Document in audit plan (`cwe-catalog-trust-audit.md` §2.8)

---

## Phase 4: Permissions (chown / ownership)

**Rules:** CWE-648, CWE-708

- [x] Read detectors + fixtures
- [x] Prefer call-facts primary for `os.Chown` when oracle-safe (both rules rewritten)
- [x] NEEDLES labels for FormValue / `owner_uid` corpus shapes
- [x] Disposition + maturity if needed (fixture-only quarantine for both)
- [x] Canary `--only CWE-648,CWE-708` — record hits (0/126 across gopdfsuit/monsoon/go-retry)
- [x] Document in audit plan (`cwe-catalog-trust-audit.md` §2.9)

---

## Phase 5: Transport TLS + JWT neighbors

**Rules:** CWE-319; CWE-358 (and document any other JWT neighbor still undated)

- [x] CWE-319: needle-primary review → disposition + call-facts primary for `ListenAndServe` (fixture-only quarantine; CVV/Number co-signals remain)
- [x] CWE-358: dated disposition — fixture-only (corpus-shaped like CWE-347; no rewrite)
- [x] NEEDLES labels for this family only
- [x] Canary `--only CWE-319,CWE-358` — record hits (0/126 across gopdfsuit/monsoon/go-retry)
- [x] Document in audit plan (`cwe-catalog-trust-audit.md` §2.10)

---

## Phase 6: Call-facts opportunity pass

Across Phases 1–5 (or remaining long-tail in the same files):

- [x] Inventory `SourceIndex.has` primary emits that map to stdlib callees already in `call_facts` (per-family notes in audit §§2.6–2.10)
- [x] Rewrite **at least one** additional rule **or** document why none of the scoped rules were safe — **rewrites:** CWE-367 (`os.Stat`+`os.ReadFile`), CWE-648/708 (`os.Chown`), CWE-319 (`*ListenAndServe`); **documented no-rewrite:** CWE-434, 1327, 358 (corpus co-signals dominate)
- [x] CWE fixtures green after each rewrite (agent runs of `go_cwe_detector_fixtures`)
- [x] Full `make lint` + `make test` before PR (orchestrator) — 401 passed

---

## Phase 7: Ship

- [x] Update `cwe-catalog-trust-audit.md` with §§2.6–2.10 (tranche 5 domain work)
- [x] PR body from `plans/PR/PR_TEMPLATE.md` with `--assignee @me`, labels, `Closes #42`
- [x] Save PR record under `plans/PR/pr-cwe-trust-tranche5.md`
- [x] PR opened for review

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

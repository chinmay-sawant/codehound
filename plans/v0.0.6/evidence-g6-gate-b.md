# Evidence — G6 Python Gate B (B1–B4) refresh

> **Issue:** [#157](https://github.com/chinmay-sawant/codehound/issues/157) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Checklist:** [`gated-g6-python-catalog.md`](./gated-g6-python-catalog.md)  
> **Prior eval:** [`../v0.0.5/phase5-g6-python-gate-eval.md`](../v0.0.5/phase5-g6-python-gate-eval.md) (2026-07-21 — remain deferred)  
> **Gate source:** [`../v0.0.5/roadmap-gates-49.md`](../v0.0.5/roadmap-gates-49.md) Gate B · [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md)  
> **Date:** 2026-07-23  
> **Base:** `35b27ec` (`origin/master` post G5 ceiling package #183)  
> **Kind:** Docs-only Gate B re-score — **no** Python rule expansion, **no** Cargo default flip, **no** marketing claim expansion

---

## Executive decision

| Field | Value |
|-------|--------|
| **Disposition** | **Remain deferred** |
| **Unlock multi-rule Python?** | **No** — B1 **FAIL**, B2 **FAIL**, B3 N/A until B1–B2, B4 **FAIL** |
| **ADR 0005** | Still **Accepted** (Option B — Demote / Go-first) |
| **Product surface** | Python stays experimental opt-in (`--features python`, single rule `SLOP101`) |
| **Close #157?** | **No** — gates unmet; leave open under epic #151 |
| **Next action** | No implementation PR until funded demand (B1) + Accepted invest/reverse ADR (B2) |

---

## Current Python capability inventory (2026-07-23)

Re-checked against `35b27ec`. Unchanged vs Phase 5 G6 eval in substance.

### Language plugin

| Item | Status |
|------|--------|
| Plugin module | `src/lang/python/` — **4** Rust files (`mod.rs`, `register.rs`, `detectors/mod.rs`, `detectors/re_compile_in_loop.rs`) |
| Grammar | `tree-sitter-python` optional (`feature = "python"`) |
| Extensions | `.py` |
| Auto-registration | `inventory::submit!` in `register.rs` |
| Cargo `default` | **`["go", "terminal-output", "cli"]`** — Python **not** included |
| Go comparison | `src/lang/go/` ≈ **257** `.rs` files; Python **4** |

### Rules / detectors

| Rule id | Detector | Pack | Role |
|---------|----------|------|------|
| **SLOP101** | `ReCompileInLoop` | General | Proof-of-life only |

**Rule count under Python plugin: 1.** No Python PERF / CWE / BP / taint packs.

### Tests and fixtures

| Surface | Status |
|---------|--------|
| Integration | `tests/python_integration.rs` — `#![cfg(feature = "python")]` |
| Fixtures | `tests/fixtures/python/sample.txt`, `safe.txt` only |
| AST walk | `tests/ast_walk_python.rs` |
| Real-module canary | **None** for Python |

### CI / product honesty

| Surface | Status |
|---------|--------|
| CI matrix | `.github/workflows/ci.yml` cell `go,python` (ADR 0005 consequence) |
| README | Opt-in experimental, single rule `SLOP101` |
| ROADMAP | “Python invest” under **Later** — funded + reverse ADR |
| Frontend | `frontend/src/data/sections.ts`: Go production; Python opt-in SLOP101 |
| ADRs under `documents/adr/` | **0001–0005 only** — no invest/reverse ADR Accepted or drafted as Accepted |

### Interpretation

Python remains a **compile-time opt-in plugin with one proof-of-life detector**. That is not a multi-rule catalog and not a second production language. Current marketing matches the demote ceiling (honesty OK for demote; not an invest reopen).

---

## Gate B evaluation (re-score)

Criteria from [`roadmap-gates-49.md`](../v0.0.5/roadmap-gates-49.md) § Gate B.

| # | Criterion | Status | Evidence / notes (2026-07-23) |
|---|-----------|--------|-------------------------------|
| **B1** | **Funding / product demand:** Explicit, time-bounded product commitment (issue + owner + success metrics)—not a residual plan checkbox. | **FAIL** | #157 is a **gated backlog** child under epic #151, not a funded invest mandate. No owner, time box, or success metrics for a multi-rule Python catalog. ROADMAP still “Later / only if funded.” No separate product demand issue accepting invest. Residual “consider Python” history is not B1. |
| **B2** | **New or reversing ADR:** Supersede or amend ADR 0005 with a written invest decision (catalog size, claim severity, default vs opt-in, marketing). Demote remains until that ADR is **Accepted**. | **FAIL** | ADR 0005 status: **Accepted** Option B (Go-first demote). `documents/adr/` lists 0001–0005 only — **no** Accepted invest/reverse ADR. Text still: do not invest in 10–20 Python rules in 0.1.x unless funded later (**revisit as a new ADR**). |
| **B3** | **Honesty bar:** README / ROADMAP / frontend / schema updated **only after** capability matches claim. | **N/A** (gated on B1–B2) | *Current* docs already match proof-of-life (pass for demote). B3 as **invest reopen** criterion remains blocked: no multi-rule claim proposed; cannot flip marketing before rules exist. |
| **B4** | **Engineering floor** (illustrative): production detectors; fixtures + real-module canaries; pack/profile story; CI as supported surface; measured productization. | **FAIL** | Only SLOP101; two synthetic fixtures; no real-module Python canary; no recommended/experimental pack split for Python beyond General; CI cell is **opt-in stub**, not a supported multi-rule product surface. |

### Pass/fail rollup

| Gate | Result |
|------|--------|
| B1 | **Fail** |
| B2 | **Fail** |
| B3 | **N/A** until B1–B2 (current honesty OK for demote only) |
| B4 | **Fail** |
| **Overall** | **Do not reopen** multi-rule Python catalog |

Delta vs Phase 5 G6 eval (2026-07-21): **none material** — same fails; master advanced on Go catalog / G4 / G5 docs, not Python capability or ADR posture.

---

## Demand status

| Question | Answer |
|----------|--------|
| Funded demand for multi-rule Python? | **No** |
| Is #157 itself demand evidence? | **No** — gated G6 parent; success criteria require Gate B + ADR before implementation |
| Who owns invest metrics if reopened? | **Unassigned** — must be named on a future invest ADR / product issue |

---

## ADR path (unchanged; required to reverse demote)

1. **B1:** Scoped product issue with owner, time box, success metrics.  
2. **B2:** Draft and **Accept** ADR amending/superseding 0005 (catalog size, claim severity, feature flags, marketing, non-goals).  
3. **B3:** Ship capability, then update README / ROADMAP / frontend / schema.  
4. **B4:** Production detectors, fixtures, real-module canaries, pack/profile, CI product surface.  
5. **Then** scoped implementation under #157 (or a new child) — not drive-by expansion.

**This refresh does not draft a Proposed invest ADR.** Without B1 funding, a draft invest ADR would invert the gate order and risk looking like demand.

---

## Explicit non-actions (this tranche)

- No new Python detectors or rules  
- No Cargo `default` / `python` feature flip  
- No edit to ADR 0005 body (still Accepted demote)  
- No marketing claim expansion (no multi-language SAST parity)  
- No G5 taint engine work; no Go CWE residuals  
- No inventing multi-rule Python without Accepted ADR  

---

## Cross-links

| Doc / issue | Role |
|-------------|------|
| [#157](https://github.com/chinmay-sawant/codehound/issues/157) | G6 child — this refresh |
| [#151](https://github.com/chinmay-sawant/codehound/issues/151) | v0.0.6 epic |
| [#49](https://github.com/chinmay-sawant/codehound/issues/49) | Gate B criteria tracker |
| [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md) | Go-first demote (Accepted) |
| [`ROADMAP.md`](../../ROADMAP.md) | “Python invest” Later |
| `src/lang/python/` | Plugin + SLOP101 only |

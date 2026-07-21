# Phase 5 G6 — Python catalog gate evaluation

> **Issue:** [#142](https://github.com/chinmay-sawant/codehound/issues/142) (G6)  
> **Parent epic:** [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate source:** [`roadmap-gates-49.md`](./roadmap-gates-49.md) Gate B · [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md)  
> **Related ledger:** [`phase5-gated-work.md`](./phase5-gated-work.md) § G6 · prior defer [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §2  
> **Branch:** `docs/phase5-g6-python-gate`  
> **Base:** `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2` (`origin/master`)  
> **Date:** 2026-07-21  
> **Kind:** Docs-only gate evaluation — **no Python rule expansion**

---

## Purpose

Evaluate Gate **B1–B4** for a multi-rule Python catalog investment and decide whether G6 may reopen for implementation under epic #136.

This document:

1. Inventories **current** Python capability honestly (as of the evaluation base).
2. Scores B1–B4 pass/fail with evidence.
3. Records the ADR path required to reverse Go-first demote.
4. Reaffirms disposition: **remain deferred** unless B1–B4 are met.

It does **not** implement rules, reverse ADR 0005, change Cargo defaults, or expand marketing claims.

---

## Decision (summary)

| Field | Value |
|-------|--------|
| **Disposition** | **Remain deferred** |
| **Unlock** | No — B1 **fail**, B2 **fail**, B3 N/A until B1–B2, B4 **fail** |
| **ADR 0005** | Still **Accepted** (Option B — Demote / Go-first) |
| **Product surface** | Python stays experimental opt-in (`--features python`, single rule `SLOP101`) |
| **Next action** | No implementation PR under #142 until funded demand + Accepted invest/reverse ADR; keep ROADMAP “Python invest” in **Later** |

---

## Current Python capability inventory

Honest inventory against Go production surface. Numbers are structural (source tree + tests), not marketing.

### Language plugin

| Item | Status |
|------|--------|
| Plugin module | `src/lang/python/` (4 Rust files: `mod.rs`, `register.rs`, `detectors/mod.rs`, `detectors/re_compile_in_loop.rs`) |
| Grammar | `tree-sitter-python` optional Cargo dep (`feature = "python"`) |
| Extensions | `.py` |
| Loop kinds | `for_statement`, `while_statement` |
| Dep extraction | `engine::dependencies::python_imports` wired via plugin `extract_deps` |
| Auto-registration | `inventory::submit!` in `register.rs` |
| Cargo default | **Not** in `default` — `default = ["go", "terminal-output", "cli"]` |

### Rules / detectors

| Rule id | Detector | Pack | Severity | Role |
|---------|----------|------|----------|------|
| **SLOP101** | `ReCompileInLoop` | General | Medium | Proof-of-life: `re.compile` (or `*.compile`) inside a loop |

**Rule count under Python plugin: 1.** There is no Python PERF pack, no Python CWE pack, no Python BP pack, and no Python taint rules.

Go comparison (order-of-magnitude, not a claim of completeness): `src/lang/go/` holds on the order of **250+** Rust files spanning PERF, CWE, BP, and taint; Python has **one** detector.

### Tests and fixtures

| Surface | Status |
|---------|--------|
| Integration | `tests/python_integration.rs` — `#![cfg(feature = "python")]`; sample fires SLOP101; safe does not |
| Fixtures | `tests/fixtures/python/sample.txt`, `safe.txt` only |
| AST walk | `tests/ast_walk_python.rs` (grammar/walk hygiene) |
| Plugin inventory | `tests/lang_plugin_inventory.rs` asserts `LanguageId::Python` only under `feature = "python"` |
| Rule counts | `tests/rule_counts_readme.rs` counts Python in `other` only when feature enabled |
| Real-module canary | **None** for Python (no pinned real Python repos / hit-rate ledger) |

### CI / product honesty

| Surface | Status |
|---------|--------|
| CI matrix | `.github/workflows/ci.yml` includes opt-in cell `go,python` (ADR 0005 consequence) |
| README | Explicit: opt-in experimental, single rule `SLOP101`; ADR 0005 linked |
| ROADMAP | “Python invest” under **Later** — funded + reverse ADR |
| Frontend | `frontend/src/data/sections.ts`: “Go (production); Python opt-in (1 experimental rule, SLOP101)” |
| ADR | 0005 Accepted demote; invest only with funding + **new ADR** |

### Interpretation

Python is a **compile-time opt-in plugin with a single proof-of-life detector**, fixture pair, and CI cell. That is **not** a multi-rule catalog, not a second production language, and not multi-language SAST parity. Marketing already matches this ceiling (honesty bar currently satisfied **for the demote posture**, not for an invest claim).

---

## Gate B evaluation (roadmap-gates-49)

Criteria from [`roadmap-gates-49.md`](./roadmap-gates-49.md) § Gate B (all required to reopen multi-rule investment). Cross-check: ADR 0005, [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §2, [`phase5-gated-work.md`](./phase5-gated-work.md) G6.

| # | Criterion | Status | Evidence / notes |
|---|-----------|--------|------------------|
| **B1** | **Funding / product demand:** Explicit, time-bounded product commitment (issue + owner + success metrics)—not a residual plan checkbox. | **FAIL** | #142 is a **gated backlog** parent under epic #136, not a funded invest mandate. No owner/time-box/success metrics for a multi-rule Python catalog. ROADMAP still “Later / only if funded.” Prior #40 / #49 records remain **defer**. No separate product demand issue accepting invest. |
| **B2** | **New or reversing ADR:** Supersede or amend ADR 0005 with a written invest decision (catalog size, claim severity, default vs. opt-in, marketing language). Demote remains in force until that ADR is **Accepted**. | **FAIL** | ADR 0005 status: **Accepted** Option B (Go-first demote). No ADR 0006+ invest/reverse draft, no Accepted amend. Text still: do not invest in 10–20 Python rules in 0.1.x unless funded later (**revisit as a new ADR**). |
| **B3** | **Honesty bar:** README / ROADMAP / frontend / schema updated **only after** capability matches claim. | **N/A** (gated on B1–B2) | *Current* docs already match proof-of-life (pass for demote). B3 as **invest reopen** criterion remains blocked: any multi-rule claim would require capability first, then marketing—cannot flip marketing before rules exist. No multi-rule claim is proposed in this eval. |
| **B4** | **Engineering floor** (illustrative, not a commitment under #49): production detectors (not proof-of-life only); fixtures + canaries on real Python modules; pack/profile story; CI as supported surface; measured cache/ignore/productization. | **FAIL** | Only SLOP101; two synthetic fixtures; no real-module Python canary; no recommended/experimental pack split for Python beyond General; CI cell is **opt-in stub**, not a supported multi-rule product surface; dep extract exists but is not productized as a second-language SLA. |

### Pass/fail rollup

| Gate | Result |
|------|--------|
| B1 | **Fail** |
| B2 | **Fail** |
| B3 | **N/A** until B1–B2 (current honesty OK for demote only) |
| B4 | **Fail** |
| **Overall** | **Do not reopen** multi-rule Python catalog |

Until **B1 and B2** are met (funding + Accepted invest/reverse ADR), leave Python off default features and leave ROADMAP “Python invest” in **Later**. B3–B4 apply as engineering/honesty follow-through after B1–B2; they are not a back-door to schedule rules from residual checkboxes.

---

## Demand status

| Question | Answer |
|----------|--------|
| Is there funded demand for a multi-rule Python catalog? | **No** |
| Is #142 itself demand evidence? | **No** — #142 is the gated G6 parent; success criteria require Gate B + ADR outcome before implementation |
| Residual plan checkboxes? | Historical “consider Python” lines in pending-work / feedback are **not** time-bounded product commitment |
| Who owns invest metrics if reopened? | **Unassigned** — must be named on a future invest ADR / product issue |

---

## ADR path (required to reverse demote)

ADR 0005 remains the authority. Path to unlock G6 implementation:

1. **Product demand record (B1):** Scoped issue or product note with owner, time box, success metrics (e.g. target rule count, FP/FN bar, real-module canary pins, default vs opt-in).
2. **New or reverse ADR (B2):** Draft and **Accept** an ADR that supersedes or amends 0005, covering at minimum:
   - Catalog size and rule domains (e.g. PERF-only vs CWE/BP)
   - Claim severity (experimental vs production second language)
   - Feature flags (stay opt-in vs add to `default`)
   - Marketing / README / frontend language
   - Explicit non-goals (runtime plugins remain permanent non-goal per 0005)
3. **Honesty bar (B3):** Ship capability, then update README / ROADMAP / frontend / schema so claims match detectors.
4. **Engineering floor (B4):** Production detectors, fixtures, real-module canaries, pack/profile story, CI product surface, measured productization of cache/ignore/deps for Python.
5. **Implementation:** Only then open or convert implementable work under #142 (or a new child) — **not** under closed #49 / #40 / #121 as drive-by expansion.

**This evaluation does not draft that ADR.** Demote is reaffirmed.

---

## Explicit non-actions (this tranche)

- No new Python rules or detectors
- No change to Cargo `default` / `python` feature semantics
- No TypeScript stubs reintroduced
- No edit to ADR 0005 body required (still Accepted demote)
- No marketing claim of multi-language SAST parity
- No scheduling of Python multi-rule work as an ordinary parallel catalog slice under epic #136 without B1–B2

---

## Cross-links

| Doc / issue | Role |
|-------------|------|
| [#142](https://github.com/chinmay-sawant/codehound/issues/142) | G6 child — this evaluation lands against it |
| [#136](https://github.com/chinmay-sawant/codehound/issues/136) | Phase 5 implementation backlog epic |
| [#49](https://github.com/chinmay-sawant/codehound/issues/49) | Roadmap gate tracker (B1–B4 definitions) |
| [`roadmap-gates-49.md`](./roadmap-gates-49.md) | Gate B criteria source of truth |
| [`phase5-gated-work.md`](./phase5-gated-work.md) | G6 reopen short form |
| [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md) | Epic ↔ G-row map |
| [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) | Prior Phase 4.4 defer (#40) |
| [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md) | Go-first demote (Accepted) |
| [`ROADMAP.md`](../../ROADMAP.md) | “Python invest” Later row |
| `src/lang/python/` | Plugin + SLOP101 only |
| `tests/python_integration.rs` | Feature-gated fixture proof |

---

## Execution checklist

### Completed (2026-07-22)

- [x] Inventory current Python capability (SLOP101 only; honest vs Go)
- [x] Evaluate Gate **B1–B4** with pass/fail and evidence
- [x] Record demand status and ADR path (ADR 0005 still Accepted demote)
- [x] Decision: **remain deferred**
- [x] No new Python rules
- [x] PR body at [`pr-phase5-g6-python.md`](./pr-phase5-g6-python.md)
- [x] Cross-link #142 / #136

### Remaining to reopen implementation

- [ ] B1 Funded / time-bounded demand with owner + metrics
- [ ] B2 New or reversing ADR Accepted (amend/supersede 0005)
- [ ] B3 Honesty bar for README/ROADMAP/frontend after capability matches claim
- [ ] B4 Engineering floor for real multi-rule second language
- [ ] New scoped implementable issue (not #142 alone as delivery)

# v0.0.5 — Phase 5 gated work (tracking complete; implementations deferred)

> **Program status (epic #105):** **TRACKING COMPLETE** — reopen criteria recorded; this tranche is done.  
> **Implementation status (G1–G6):** still **DEFERRED** until reopen criteria met.  
> **Implementation backlog:** epic [#136](https://github.com/chinmay-sawant/codehound/issues/136) · children [#137](https://github.com/chinmay-sawant/codehound/issues/137)–[#142](https://github.com/chinmay-sawant/codehound/issues/142) · [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md)  
> **Historical trackers (closed):** [#120](https://github.com/chinmay-sawant/codehound/issues/120) · [#121](https://github.com/chinmay-sawant/codehound/issues/121)  
> **Plan source:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §5.1–5.2  
> **Kind:** Docs-only reopen criteria (not a feature mandate)  
> **Date:** 2026-07-21

---

## Banner — tracking complete · implementations remain deferred

| | |
|--|--|
| **Epic #105 Phase 5 work** | **Done.** Single plan record, status table, reopen criteria, and non-actions shipped. Trackers may close with the program integration PR. |
| **This file going forward** | Permanent gate ledger. G1–G6 stay **deferred** until criteria below are met. |
| **Implementations** | Use backlog children **#137–#142** only after reopen evidence is recorded on that issue. Do not re-use closed #120 / #121. |
| **Not authorized by** | Closed trust batches, noise-reduce canaries, recommended-pack pilots, or unchecked historical plan boxes. |

**Explicit non-actions until a successor implementable issue exists:**

- No broad BP-66+ rule expansion or research-list bulk implementation
- No CWE-277 maturity promotion to `structural`
- No generalization of fixture-only CWE/BP rules without AST/fact proof replacement
- No optional `--typed` / `go/packages` / typed fact layer
- No external-package taint wiring, decoder-receiver taint, or channel/goroutine flow modeling
- No Python multi-rule catalog investment or ADR 0005 reverse

---

## Purpose

Phase 5 of the parallel catalog program was **track-and-record**, not implement. That tracking is complete. This remains the single plan record for:

1. **Phase 5.1** — BP expansion and CWE promotion gates (#120)
2. **Phase 5.2** — Advanced analysis investments (#121)

Related but separate gate trackers (do not collapse into this file):

| Tracker | Scope |
|---------|--------|
| [`roadmap-gates-49.md`](./roadmap-gates-49.md) (#49) | Typed Go A1–A6 and Python B1–B4 reopen criteria |
| [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) (#40) | Prior defer decision for typed Go + Python |
| [`taint-capability-decision.md`](./taint-capability-decision.md) | Taint ceiling table (decoder / external-package / channel) |
| [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3 | Structural promotion bar for any CWE |

---

## Status table

| ID | Item | Phase | Disposition | Implement issue | Gate to reopen (summary) |
|----|------|-------|-------------|-----------------|--------------------------|
| G1 | Broad BP-66+ expansion | 5.1 | **Deferred** | [#137](https://github.com/chinmay-sawant/codehound/issues/137) | High-signal real-module pattern + overlap + fixture + canary |
| G2 | CWE-277 Structural promotion | 5.1 | **Deferred** | [#138](https://github.com/chinmay-sawant/codehound/issues/138) | Actionable real-module hit + mode/scope negatives + §1.3 bar |
| G3 | Generalization of fixture-only rules | 5.1 | **Deferred** | [#139](https://github.com/chinmay-sawant/codehound/issues/139) | Corpus co-signals replaced by real AST/fact proof + §1.3 bar |
| G4 | Optional typed Go / `go/packages` | 5.2 | **Deferred** | [#140](https://github.com/chinmay-sawant/codehound/issues/140) | All Roadmap Gate #49 criteria (A1–A6) met |
| G5 | External-package taint, decoder receivers, channel/goroutine flows | 5.2 | **Deferred** | [#141](https://github.com/chinmay-sawant/codehound/issues/141) | Stronger type/concurrent data-flow contracts + taint decision |
| G6 | Python catalog investment | 5.2 | **Deferred** | [#142](https://github.com/chinmay-sawant/codehound/issues/142) | Funded demand + new/reversed Go-first ADR (#49 B1–B2) |

All rows: **implementation deferred**. Tracking for this program is complete; do not implement until a successor issue is opened after reopen criteria are satisfied.

---

## Phase 5.1 — BP and CWE promotion gates (#120)

**Plan:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §5.1  
**Structural bar:** [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3

### G1 — Broad BP-66+ expansion

| Field | Value |
|-------|--------|
| **Disposition** | Deferred |
| **Why deferred** | Historical BP research lists (parts A–F, CHECKLIST deferred ledger) are candidate inventories, not authorized backlog. Shipping bulk rules without proof boundaries creates noise and pack-trust risk. |
| **Evidence / prior disposition** | [`bp-candidates-disposition.md`](./bp-candidates-disposition.md), [`bp-proof-boundary-notes.md`](./bp-proof-boundary-notes.md), Phase 4 dispositions in [`pending-work.md`](./pending-work.md) |

**Reopen criteria (all required):**

1. A **concrete** high-signal pattern observed on pinned real modules (not fixture-only invent).
2. Overlap analysis vs existing BP/CWE/staticcheck/noctx rules (no retire-duplicate).
3. Vulnerable + safe fixtures with renamed near-miss negatives.
4. Release-binary canary on the standard corpus with an agreed FP budget.
5. New scoped implementable issue (not #120, not bulk research checkboxes).

### G2 — CWE-277 Structural promotion

| Field | Value |
|-------|--------|
| **Disposition** | Deferred (remain Heuristic until bar met) |
| **Why deferred** | File-permissions tranche generalized call-facts but canary did not supply an actionable hit that justifies structural maturity; mode variants (`0o777`, alternate umask) and broader scope negatives were explicitly held back. |
| **Evidence** | [`cwe-file-permissions-canary.md`](./cwe-file-permissions-canary.md), [`cwe-file-permissions-trust.md`](./cwe-file-permissions-trust.md), completed family under epic #85 / #94 |

**Reopen criteria (all required):**

1. Reviewed **actionable** real-module hit (not zero-hit canary alone).
2. Broader mode-variant and scope **negatives** that keep the false-positive budget bounded.
3. Primary emit meets audit §1.3 (AST/call facts/callee classification/taint — not corpus mode literals as sole proof).
4. Maturity table + profile eligibility updated in the **same** change as promotion.
5. New scoped implementable issue (do not reopen completed file-permissions family wholesale).

### G3 — Generalization of fixture-only rules

| Field | Value |
|-------|--------|
| **Disposition** | Deferred per rule until proof replaces corpus co-signals |
| **Why deferred** | Fixture-only means available under `--profile all`, not production-certified. Promoting or “generalizing” while emit still depends on paths, names, formulas, or SourceIndex co-signals violates the catalog trust bar. |
| **Evidence** | Program success criteria; audit §1.1–1.3; Phase 1–2 FO quarantines under #95 / #105 |

**Reopen criteria (all required):**

1. Corpus paths, identifiers, formulas, or co-signals are **replaced** (not merely supplemented) by real AST/fact/taint proof as the primary emit signal.
2. Renamed/structurally varied negatives exist; needles are negative prefilters only.
3. Reviewed real-module evidence or documented FP boundary per §1.3.
4. One rule (or tightly scoped family) per successor issue — no bulk FO → Heuristic/Structural flips.

---

## Phase 5.2 — Advanced analysis investments (#121)

**Plan:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §5.2  
**Gate detail:** [`roadmap-gates-49.md`](./roadmap-gates-49.md) · prior defer: [`roadmap-investments-decision.md`](./roadmap-investments-decision.md)

### G4 — Optional typed Go facts / `go/packages`

| Field | Value |
|-------|--------|
| **Disposition** | Deferred until Roadmap Gate #49 |
| **Why deferred** | Tree-sitter-only default preserves speed and offline scans. Typed mode is a toolchain-dependent second fact pipeline; closed trust/noise work does **not** unlock it. |

**Reopen criteria:** All of Gate A (A1–A6) in [`roadmap-gates-49.md`](./roadmap-gates-49.md):

| # | Criterion (short) |
|---|-------------------|
| A1 | PERF pack product trust sign-off for typed-mode readiness |
| A2 | Catalog honesty boundary (typed facts not papering over trust holes) |
| A3 | Written FN/FP capability contract |
| A4 | Architecture sketch (tree-sitter primary; optional typed layer) |
| A5 | Cost acceptance (toolchain, latency, CI) |
| A6 | Non-blocker policy (not a release/recommended dependency) |

Plus a **new scoped implementation issue** (not #121, not #49 as delivery).

### G5 — External-package taint, decoder receivers, channel/goroutine flows

| Field | Value |
|-------|--------|
| **Disposition** | Deferred |
| **Why deferred** | Shipped taint contract records these as explicit ceilings / unsupported flows. Fake edges would violate ADR 0003 honesty (prefer FN over pretend coverage). |
| **Evidence** | [`taint-capability-decision.md`](./taint-capability-decision.md); `documents/taint.md`; ROADMAP non-goal: security-grade whole-program taint |

**Reopen criteria (all required):**

1. Written FP/FN contract for the specific enhancement (external-package summaries, `(*Decoder).Decode` receivers, or concurrent channel/goroutine handoffs).
2. Stronger type and/or concurrent data-flow design that does not invent assignment edges for unsupported constructs.
3. Fixtures + integration tests + representative-project canaries.
4. Dependency clarity: decoder receivers and external-package wiring may need typed or package-graph facts (coordinate with G4 / #49 — do not sneak typed mode under a taint ticket).
5. New scoped implementable issue (not #121).

### G6 — Python catalog investment

| Field | Value |
|-------|--------|
| **Disposition** | Deferred pending demand + ADR |
| **Why deferred** | ADR 0005 Option B (Go-first demote) remains accepted. Python is experimental opt-in (`SLOP101` only). |

**Reopen criteria:** Gate B in [`roadmap-gates-49.md`](./roadmap-gates-49.md):

| # | Criterion (short) |
|---|-------------------|
| B1 | Funded / time-bounded product demand with owner and success metrics |
| B2 | New or reversing ADR Accepted (supersede/amend ADR 0005) |
| B3 | Honesty bar for README/ROADMAP/frontend/schema after capability matches claim |
| B4 | Engineering floor for a real second language (illustrative; not a commitment under this tracker) |

---

## How to reopen (process)

1. Record evidence that the relevant reopen criteria are met (comment on a closed tracker, this file, or a short plan note).
2. Open a **new implementable child issue** with a single owned seam, fixtures, canary command, and out-of-scope list.
3. Do **not** re-open #120 / #121 for implementation; those were **tracking** tickets for epic #105 (closed when tracking shipped).
4. Later catalog epics must **not** schedule G1–G6 as ordinary parallel catalog slices without meeting reopen criteria.

---

## Lifecycle

| State | When |
|-------|------|
| **Tracking complete (current for #105)** | Gates reaffirmed in this file; #120 / #121 tracking success criteria met; may close with Phase 3–5 integration |
| **Implementation still deferred** | G1–G6 criteria unmet; no successor implementation issue |
| **Partially reopened** | One successor issue open for a single G-row; other rows remain deferred |
| **Tracker historical** | Closed after tracking landed; new work uses new issue numbers only |

Success criteria for **this docs tranche** (epic #105 Phase 5):

- [x] Single plan record for Phase 5.1 + 5.2 with status table and reopen criteria
- [x] Banner distinguishes **tracking complete** vs **implementation deferred**
- [x] Cross-links to #120, #121, #105, program §5.1–5.2, #49 gates, audit §1.3, taint decision
- [x] No implementation of BP expansion, CWE-277 promotion, typed Go, or Python catalog

---

## Related

- Implementation backlog: [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md) · epic [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
- Ledger: [`parallel-catalog-program.md`](./parallel-catalog-program.md) Phase 5  
- Historical trackers: [#120](https://github.com/chinmay-sawant/codehound/issues/120), [#121](https://github.com/chinmay-sawant/codehound/issues/121)  
- Closed program epic: [#105](https://github.com/chinmay-sawant/codehound/issues/105)  
- Roadmap gates: [#49](https://github.com/chinmay-sawant/codehound/issues/49) · [`roadmap-gates-49.md`](./roadmap-gates-49.md)  
- Investments decision: [`roadmap-investments-decision.md`](./roadmap-investments-decision.md)  
- Structural bar: [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §1.3  
- Taint ceilings: [`taint-capability-decision.md`](./taint-capability-decision.md)  
- ADR: [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md)  
- Roadmap: [`ROADMAP.md`](../../ROADMAP.md)  

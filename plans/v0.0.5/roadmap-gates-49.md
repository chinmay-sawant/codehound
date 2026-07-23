# v0.0.5 — Roadmap gates: optional typed Go and Python

> **Issue:** [#49](https://github.com/chinmay-sawant/codehound/issues/49)  
> **Parent epic:** [#44](https://github.com/chinmay-sawant/codehound/issues/44)  
> **Status:** **Gates closed / deferred** — tracker only; no implementation under this issue.  
> **Date:** 2026-07-19  
> **Kind:** Docs-only reopen criteria (not a feature mandate)

---

## Purpose

Hold explicit **reopen criteria** for two ROADMAP “Later” investments so they are not started from residual checkboxes or under closed trust work:

1. Optional typed Go facts (`--typed` / `go/packages`)
2. Python multi-rule investment (beyond experimental `SLOP101`)

This document **does not** implement either investment, change feature flags, or reverse [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md). Product disposition remains **defer**, as recorded in [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) (#40).

---

## Closed foundation (do not reopen under these)

Trust and process work that **closed** before this gate tracker. Implementations for typed Go or Python must **not** land as follow-ups on these tickets; open a **new scoped issue** only when the reopen criteria below are met.

| Work | Role | Outcome |
|------|------|---------|
| PR [#38](https://github.com/chinmay-sawant/codehound/pull/38) / noise-reduce-1 | PERF/full-catalog noise canary | Closed: pinned `real-repos/gorl` full-catalog **53** findings; recommended remains **0** on that canary ([`noise-reduce-1.md`](./noise-reduce-1.md)) |
| PR [#41](https://github.com/chinmay-sawant/codehound/pull/41) | CWE catalog trust (prior tranche) | Merged — long-tail honesty progress; not a typed-mode or Python mandate |
| PR [#43](https://github.com/chinmay-sawant/codehound/pull/43) / issue [#42](https://github.com/chinmay-sawant/codehound/issues/42) | CWE trust tranche 5 | Merged — domain audits + process templates; residual CWE work is [#45](https://github.com/chinmay-sawant/codehound/issues/45), not #49 |
| Issue [#40](https://github.com/chinmay-sawant/codehound/issues/40) | Phase 4.4 roadmap investments decision | **Closed:** both investments deferred with written preconditions ([`roadmap-investments-decision.md`](./roadmap-investments-decision.md)) |
| Issues [#39](https://github.com/chinmay-sawant/codehound/issues/39) / [#42](https://github.com/chinmay-sawant/codehound/issues/42) | CWE process gates | **Closed** — catalog honesty continues under [#45](https://github.com/chinmay-sawant/codehound/issues/45) only |

**Interpretation:** Recommended-pack trust, noise-reduce closure, and CWE tranches strengthen the **Go tree-sitter** product surface. They do **not** by themselves authorize optional `go/packages` or a multi-rule Python catalog.

---

## Gate A — Optional `--typed` / `go/packages`

### Current disposition

**Defer.** Stay tree-sitter-only for speed and offline default. Do not design, ship, or prototype typed Go analysis in 0.1.x under #49.

| Source | Statement |
|--------|-----------|
| [`ROADMAP.md`](../../ROADMAP.md) — Next | “Typed Go facts — Optional `--typed` / go/packages only if PERF pack trusted” |
| [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §1 | Defer; preconditions 1–6 for reconsideration |
| [`plans/feedback/10072026/go.md`](../feedback/10072026/go.md) §18 | Hybrid `go/packages` is a **big bet**; do not block 0.1.0 on typed mode |

### Reopen criteria (all required)

Reopen **only** with a **new scoped GitHub issue** (not under #38/#41/#43/#40/#42, and not as a drive-by under #45) when **all** of the following hold:

| # | Criterion | Met? |
|---|-----------|------|
| A1 | **PERF pack trust (product):** Documented acceptance that S-tier / recommended PERF (and any broader PERF profile under consideration) meets an agreed external FP rate on pinned real modules—beyond the 20-finding pilot (95% actionable) and canary hygiene alone. | **Yes** — 2026-07-23 Gate A package ([`../v0.0.6/evidence-g4-gate-a.md`](../v0.0.6/evidence-g4-gate-a.md) §A1); P1 pilot stable |
| A2 | **Catalog honesty boundary:** Relevant CWE long-tail / NEEDLES gaps are either closed or explicitly kept/quarantined so typed facts are not asked to paper over detector trust holes ([#45](https://github.com/chinmay-sawant/codehound/issues/45) may proceed independently without unlocking typed mode). | **Yes** — R1–R8 + G3 FO ledger in Gate A §A2 |
| A3 | **Capability contract:** Written FN/FP contract for what typed facts improve (e.g. receiver types, build tags, same-package signatures) vs. what remains unsupported (channel/goroutine handoffs, whole-program taint — see ROADMAP non-goals and [`taint-capability-decision.md`](./taint-capability-decision.md)). | **Yes** — [`../v0.0.6/g4-typed-capability-contract.md`](../v0.0.6/g4-typed-capability-contract.md) |
| A4 | **Architecture sketch:** Detector APIs stay tree-sitter-primary; typed facts are an **optional** layer feeding the same rules; offline / no-toolchain default preserved. | **Yes** — [`../v0.0.6/g4-typed-architecture.md`](../v0.0.6/g4-typed-architecture.md) |
| A5 | **Cost acceptance:** Measured impact of requiring a Go toolchain for `--typed`, scan latency/memory vs. tree-sitter-only, and CI matrix implications. | **Yes** — external `packages.Load` probe §A5; opt-in cost only |
| A6 | **Non-blocker policy:** Typed mode must not become a release or recommended-pack dependency. | **Yes** — held |

Gate A **PASS** 2026-07-23 on #155. Product `go/packages` integration still requires a **scoped implementation tranche** (not this tracker alone). ROADMAP “Typed Go facts” may move from pure Later to **gated-ready / impl open** when the impl issue is filed.

### Explicit non-actions (Gate A)

- No `--typed` CLI flag, no `go/packages` / `go/types` integration, no typed fact layer spike as delivery under #49.
- No claiming that closed PRs #38 / #41 / #43 unlocked typed mode.

---

## Gate B — Python multi-rule investment

### Current disposition

**Defer.** Python remains experimental opt-in only (`--features python`, single rule `SLOP101`), consistent with ADR 0005 Option B (Go-first demote).

| Source | Statement |
|--------|-----------|
| [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md) | Demote accepted; do not invest in 10–20 Python rules in 0.1.x unless funded later (**revisit as a new ADR**) |
| [`ROADMAP.md`](../../ROADMAP.md) — Next | “Python invest — Only if funded — reverse ADR 0005 demote with a new ADR” |
| [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §2 | Defer; funding + new/reversed ADR required |

### Reopen criteria (all required)

| # | Criterion | Met? |
|---|-----------|------|
| B1 | **Funding / product demand:** Explicit, time-bounded product commitment (issue + owner + success metrics)—not a residual plan checkbox. | **No** |
| B2 | **New or reversing ADR:** Supersede or amend ADR 0005 with a written invest decision (catalog size, claim severity, default vs. opt-in, marketing language). Demote remains in force until that ADR is **Accepted**. | **No** — ADR 0005 still Accepted (demote) |
| B3 | **Honesty bar:** README / ROADMAP / frontend / schema updated only after capability matches claim. | N/A until B1–B2 |
| B4 | **Engineering floor (illustrative, not a commitment):** production detectors (not proof-of-life only); fixtures + canaries on real Python modules; pack/profile story; CI matrix for `--features python` as a supported surface; measured cache/ignore/productization. | **No** |

Until B1–B2 are met, leave ROADMAP “Python invest” in **Later** and keep Python off default features.

### Explicit non-actions (Gate B)

- No Python rule expansion, no re-adding TypeScript stubs, no default-feature change for Python under #49.
- No edit to ADR 0005 text required for this tracker; demote is **reaffirmed**.

---

## Summary

| Investment | Disposition | Gate to reopen | Tracker |
|------------|-------------|----------------|---------|
| `--typed` / `go/packages` | **Defer** | A1–A6 + new scoped issue | #49 (this doc) |
| Python multi-rule invest | **Defer** | B1–B2 (ADR reverse) + engineering floor | #49 (this doc) |

| Closed trust (not an unlock) | |
|------------------------------|--|
| #38 noise-reduce / PERF canary | Foundation only |
| #41 / #43 CWE trust tranches | Foundation only |
| #40 investments decision | Prior defer record |

---

## Issue #49 lifecycle

| State | When |
|-------|------|
| **Open (current)** | Gates documented; both investments deferred; linked from ROADMAP |
| **Still open** | Product has not accepted A1–A6 or B1–B2; no successor implementation issue |
| **Close** | Either (a) successor issues implement under explicit approval and this tracker is obsolete, or (b) product marks both investments **wontfix** for a release series |

Success criteria for this docs tranche:

- [x] Gate criteria documented in this file
- [x] Linked from [`ROADMAP.md`](../../ROADMAP.md) Next table
- [x] Decision record cross-linked: [`roadmap-investments-decision.md`](./roadmap-investments-decision.md), [ADR 0005](../../documents/adr/0005-multi-lang-honesty.md)
- [x] Closed trust work #38 / #41 / #43 cited as foundation, not unlock

---

## Related

- Epic: [#44](https://github.com/chinmay-sawant/codehound/issues/44)  
- Gate tracker: [#49](https://github.com/chinmay-sawant/codehound/issues/49)  
- Prior decision: [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) (#40)  
- ADR: [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md)  
- Roadmap: [`ROADMAP.md`](../../ROADMAP.md)  
- PERF canary: [`noise-reduce-1.md`](./noise-reduce-1.md) (PR #38)  
- Taint ceilings (typed facts do not erase): [`taint-capability-decision.md`](./taint-capability-decision.md)  
- Residual CWE (independent): [#45](https://github.com/chinmay-sawant/codehound/issues/45)  

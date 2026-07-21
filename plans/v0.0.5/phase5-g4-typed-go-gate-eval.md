# Phase 5 G4 — Typed Go Gate A evaluation (remain deferred)

> **Issue:** [#140](https://github.com/chinmay-sawant/codehound/issues/140) (G4)  
> **Parent epic:** [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate source of truth:** [`roadmap-gates-49.md`](./roadmap-gates-49.md) Gate A (A1–A6)  
> **Tracker row:** [`phase5-gated-work.md`](./phase5-gated-work.md) G4  
> **Prior defer:** [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) (#40)  
> **Status:** **REMAIN DEFERRED** — docs-only evidence pass; **no** `go/packages` integration, **no** `--typed` flag, **no** Cargo deps  
> **Evaluation date:** 2026-07-22  
> **Base SHA:** `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2` (`origin/master`)  
> **Checklist plan:** this file (execution checklist below)

---

## Execution checklist

### Completed (2026-07-22)

- [x] Read Gate A source of truth (`roadmap-gates-49.md`)
- [x] Walk **A1–A6** with pass/fail + evidence as of today
- [x] Decision: **remain deferred** (not all A1–A6 pass)
- [x] List blockers and reopen path
- [x] Minimal optional typed-layer design sketch (**no code**)
- [x] Explicit non-actions: no `go/packages`, no Cargo deps, no `--typed`
- [x] Cross-link #140 / #136 / ROADMAP Later row

### Remaining to reopen implementation

- [ ] A1 PERF pack typed-mode readiness sign-off
- [ ] A2 Typed-mode honesty ledger
- [ ] A3 Written FN/FP capability contract
- [ ] A4 Accepted architecture sketch
- [ ] A5 Cost measurements accepted
- [x] A6 Non-blocker policy (already held)
- [ ] New scoped implementation issue (not #140 alone as delivery)

---

## Purpose

Walk Gate A (A1–A6) with **evidence** as of today and record whether G4 may leave deferred status. This document satisfies #140 success criterion “Gate A evidence recorded” for the **evaluation** half only. It does **not** authorize design spikes that pull in the Go toolchain, and it does **not** implement a typed fact layer.

**Binding decision rule** (from Gate A): reopen only when **all** of A1–A6 hold **and** a **new scoped implementation issue** exists (not #140 alone as delivery, not closed #49 / #121 as code tickets).

---

## Executive decision

| Field | Value |
|-------|--------|
| **Decision** | **Remain deferred** |
| **All A1–A6 pass?** | **No** |
| **Implement `go/packages` / `--typed`?** | **No** |
| **ROADMAP “Typed Go facts”** | Stay **Later** |
| **#140** | Keep open as gated backlog parent; evaluation complete; implementation blocked |

Closed trust work (noise-reduce, recommended pilot, CWE tranches) strengthens the **tree-sitter** Go product surface. It does **not** unlock a toolchain-dependent second fact pipeline.

---

## Gate A evidence table (as of 2026-07-22)

| # | Criterion | Status | Evidence (paths / statements) | Blocker if fail |
|---|-----------|--------|---------------------------------|-----------------|
| **A1** | **PERF pack trust (product):** Documented acceptance that S-tier / recommended PERF (and any broader PERF profile under consideration) meets an agreed **external FP rate** on pinned real modules—**beyond** the 20-finding pilot (95% actionable) and canary hygiene alone. | **FAIL** | Pilot + stop-the-line: [`recommended-pack-pilot.md`](./recommended-pack-pilot.md) — 19/20 = 95% actionable; core 40/41 = 97.6%; gorl recommended **0**. Full-catalog hygiene: [`noise-reduce-1.md`](./noise-reduce-1.md) closed at **53** findings on pinned `real-repos/gorl` (recommended still 0). ROADMAP Current cites the pilot. **Missing:** product document or issue comment that explicitly **accepts PERF as typed-mode-ready** against an agreed external FP rate (beyond pilot + canary). Prior decision already stated pilot + noise-reduce do **not** alone authorize `go/packages` ([`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §1; [`roadmap-gates-49.md`](./roadmap-gates-49.md) A1). | Product sign-off that PERF (recommended / S-tier, and any broader PERF profile in scope) meets a named external FP bar on pinned modules; record on a scoped issue. |
| **A2** | **Catalog honesty boundary:** Relevant CWE long-tail / NEEDLES gaps are either closed or explicitly keep/quarantined so typed facts are **not** asked to paper over detector trust holes (#45 may proceed independently without unlocking typed mode). | **PARTIAL → FAIL for reopen** | Tranches merged as foundation only: PR #38 / #41 / #43; residual program under [#45](https://github.com/chinmay-sawant/codehound/issues/45) and parallel catalog Phases (audit §1.3). Fixture-only quarantine and NEEDLES process exist ([`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md), [`cwe-catalog-trust-45.md`](./cwe-catalog-trust-45.md)). Phase 5 G1–G3 still deferred (BP-66+, CWE-277 structural, FO generalization — [`phase5-gated-work.md`](./phase5-gated-work.md)). **Missing:** written boundary that lists which residual trust holes are accepted **without** expecting typed mode to fix them, and which (if any) typed facts would improve **after** honesty is settled. | Explicit keep/quarantine ledger for residual long-tail relevant to typed-mode motivation; statement that typed mode will not substitute for §1.3 structural bar or FO → maturity flips. |
| **A3** | **Capability contract:** Written FN/FP contract for what typed facts improve (e.g. receiver types, build tags, same-package signatures) vs. what remains unsupported (channel/goroutine handoffs, whole-program taint). | **FAIL** | Taint ceilings document what **taint** does **not** do today ([`taint-capability-decision.md`](./taint-capability-decision.md)); ROADMAP non-goal: security-grade whole-program taint. Feedback note only: hybrid is a **big bet** ([`plans/feedback/10072026/go.md`](../feedback/10072026/go.md) §18). **No** typed-mode FN/FP contract (what rules gain precision, what stays unsupported, FP risk of wrong types / incomplete packages). | New short contract doc (or ADR amendment) listing improve / still-unsupported / non-goals for optional typed facts. |
| **A4** | **Architecture sketch:** Detector APIs stay tree-sitter-primary; typed facts are an **optional** layer feeding the same rules; offline / no-toolchain default preserved. | **FAIL** (not started as approved design) | Detectors today are tree-sitter / AST / SourceIndex only (`src/core/detector.rs`, Go plugin under `src/lang/go/`). Cargo features: `go` → `tree-sitter-go` only; **no** `go/packages` / `go/types` bridge. CLI: **no** `--typed`. go.md §18 recommends designing APIs so a later layer can feed the same rules — **aspiration only**. Minimal sketch **in this eval** (§ below) is **informative for reopen**, not an A4 pass until product accepts it on a design issue. | Accepted architecture note (this sketch or successor) plus API seams named; offline default explicit. |
| **A5** | **Cost acceptance:** Measured impact of requiring a Go toolchain for `--typed`, scan latency/memory vs. tree-sitter-only, and CI matrix implications. | **FAIL** | Cold-scan budget holds tree-sitter path only ([`perf-eval-decision.md`](./perf-eval-decision.md), [`perf-budget-48.md`](./perf-budget-48.md), pilot cold-scan ~0.52–0.85s gopdfsuit). **No** prototype or measurement of `go/packages` load, type-check wall, memory, or “Go toolchain required in CI for `--typed`” matrix. | Benchmark plan + recorded numbers on pinned modules; CI/product acceptance of toolchain cost when flag is set. |
| **A6** | **Non-blocker policy:** Typed mode must not become a release or recommended-pack dependency. | **PASS** (policy retained) | Policy stated in Gate A, investments decision §1.6, phase5 non-actions, and #140 out-of-scope. Default features remain tree-sitter Go; recommended pack does not require types. **Not** an implementation unlock: policy pass does not flip G4. | — (keep policy in any future design) |

### Summary counts

| Result | Criteria |
|--------|----------|
| **PASS** | A6 only |
| **PARTIAL** | A2 (process exists; typed-mode honesty boundary not recorded) |
| **FAIL** | A1, A2 (for reopen), A3, A4, A5 |

**Reopen math:** all required → **not satisfied**.

---

## Blockers (ordered)

1. **A1 — Product PERF “typed-mode-ready” sign-off** beyond pilot 95% + noise-reduce canary.
2. **A3 — Typed capability FN/FP contract** (distinct from taint ceiling table).
3. **A4 — Accepted architecture** (tree-sitter primary; optional layer; offline default) — sketch below is draft only.
4. **A5 — Cost measurement** (toolchain, latency, memory, CI) before any integration PR.
5. **A2 — Honesty boundary** so typed mode is not scheduled to paper over FO / NEEDLES / residual CWE gaps.
6. **Process:** new **implementation** issue after A1–A6 recorded green; do not treat #140 evaluation as code authorization; do not smuggle typed mode under G5 taint tickets ([`phase5-gated-work.md`](./phase5-gated-work.md) G5 §4).

---

## What is already strong (foundation, not unlock)

| Foundation | Role | Does **not** unlock |
|------------|------|---------------------|
| Recommended-pack pilot 95% / 97.6% | CI default trust | A1 typed-mode-ready bar |
| noise-reduce-1 closed (gorl 53 / rec 0) | Full-catalog hygiene | `go/packages` |
| Cold-scan under budget | Perf rewrite hold | Typed cost acceptance |
| CWE trust tranches + FO quarantine | Catalog honesty process | A2 typed-mode boundary |
| Taint explicit FNs (channel/goroutine, external pkg, decoder receivers) | Honesty over fake edges | Typed implementation |
| Detector lifecycle / plugin seams | Future optional facts **possible** | A4 acceptance |

---

## Minimal design sketch — optional typed layer (no code)

> **Status of this section:** **Draft only** for reopen discussion. Does **not** satisfy A4 until product accepts it on a design issue. **Do not implement** under #140.

### Goals

- Optional precision for rules that today guess from selectors / names (e.g. method receivers, concrete types behind interfaces, build-tag–accurate files).
- Same rule IDs and finding construction path as tree-sitter mode.
- Default and recommended-pack scans stay **offline**, **no Go toolchain**, tree-sitter-only.

### Non-goals

- Security-grade whole-program taint (ROADMAP non-goal unchanged).
- Making `--typed` (or config equivalent) required for release, CI recommended gate, or pack membership.
- Replacing tree-sitter parse as the primary unit pipeline.
- Channel/goroutine concurrent DF “solved by types” (see G5 / taint decision).

### Layering (conceptual)

```
Scan request
  ├─ always: walk → tree-sitter parse → ParsedUnit → SourceIndex / AST facts
  │            → Detector::run (existing)
  └─ only if typed enabled AND toolchain available:
       go/packages load (module graph) → go/types info
       → TypedFactProvider (query: type of expr, method set, package path)
       → same detectors optionally consult TypedFactProvider
          (missing facts ⇒ same behavior as tree-sitter-only, not hard fail)
```

### API principles (from go.md §18 + current `Detector` trait)

1. **Tree-sitter primary:** `Detector::run` continues to receive `ParsedUnit` / `ScanContext` as today (`src/core/detector.rs`).
2. **Optional facts:** typed information is a **side channel** (context field or trait object), never the only way to emit.
3. **Degrade gracefully:** if packages fail to load (no `go`, incomplete module, network GOPROXY issues), scan completes tree-sitter-only; emit diagnostics, not abort of default profile.
4. **Same rules:** no parallel “typed-only” rule catalog for 0.1.x; precision upgrades are rule-internal.
5. **Session lifecycle:** load package graph once per scan (`begin_scan`), not per file; align with existing detector session hooks.

### Product / CLI (illustrative — not shipping)

| Surface | Sketch |
|---------|--------|
| Flag / config | e.g. `--typed` or `[analysis] typed = true` — **opt-in** |
| Default | `false` / off |
| Recommended pack | **must not** require typed |
| Docs | cost, toolchain requirement, when to use |

### Cost dimensions to measure before A5 pass

| Dimension | Tree-sitter baseline | Typed (to measure) |
|-----------|----------------------|--------------------|
| Toolchain | None | `go` on PATH; module download policy |
| Wall time | Sub-second cold gopdfsuit class | packages.Load + typecheck delta |
| Memory | ~tens of MiB class (existing notes) | typechecker RSS |
| CI | No Go required for CodeHound build tests of detectors | optional job only if flag tested |
| Offline | Yes | No (or vendor-only constrained mode — product choice) |

### Coordination with G5

Decoder receivers and external-package taint may **want** typed or package-graph facts ([`phase5-gated-work.md`](./phase5-gated-work.md) G5). That is a **dependency arrow**, not a back door: G5 must not land fake typed mode under a taint ticket. If both reopen, sequence: A1–A6 + typed design issue → then taint contracts that consume typed facts.

---

## Explicit non-actions (this evaluation)

- No `--typed` CLI flag, config key, or feature flag implementation.
- No `go/packages` / `go/types` / CGO / external Go process integration.
- No `Cargo.toml` dependency changes for typed analysis.
- No detector rewrites that assume types.
- No claim that closed PRs #38 / #41 / #43 / #105 or pilot docs unlocked typed mode.
- No change to recommended-pack membership or default features.

---

## How to reopen later

1. Turn each FAIL/PARTIAL row green with linked evidence (product comment, contract doc, measurements).
2. Accept (or revise) the architecture sketch on a **design** issue.
3. Open a **new implementable** issue (single owned seam: e.g. “optional TypedFactProvider behind flag + one pilot rule”) — not bulk under #140 without evidence.
4. Keep A6: typed never blocks release or recommended CI.
5. Update this file’s status table and [`roadmap-gates-49.md`](./roadmap-gates-49.md) Met? column when product accepts.

---

## Related

| Doc / issue | Role |
|-------------|------|
| [#140](https://github.com/chinmay-sawant/codehound/issues/140) | G4 backlog parent |
| [#136](https://github.com/chinmay-sawant/codehound/issues/136) | Phase 5 implementation epic |
| [#49](https://github.com/chinmay-sawant/codehound/issues/49) | Roadmap gate tracker (A1–A6 / B1–B4) |
| [`roadmap-gates-49.md`](./roadmap-gates-49.md) | Gate A criteria |
| [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) | Prior #40 defer |
| [`phase5-gated-work.md`](./phase5-gated-work.md) | G4 row + non-actions |
| [`phase5-implementation-backlog.md`](./phase5-implementation-backlog.md) | Epic map |
| [`taint-capability-decision.md`](./taint-capability-decision.md) | Taint ceilings; does not alone justify typed |
| [`plans/feedback/10072026/go.md`](../feedback/10072026/go.md) §18 | Hybrid big-bet note |
| [`ROADMAP.md`](../../ROADMAP.md) | Typed Go facts → Later |

---

## Checklist (#140 evaluation slice)

- [x] Walk A1–A6 with pass/fail + evidence
- [x] Decision: **remain deferred**
- [x] Blockers listed
- [x] Minimal optional-layer design sketch (no code)
- [x] Explicit non-actions (no go/packages, no Cargo deps)
- [ ] Implementation / tests — **blocked** until A1–A6 all pass + new scoped issue

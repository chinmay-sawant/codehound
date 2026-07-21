# Phase 5 G5 — Advanced taint ceiling evaluation (remain deferred)

> **Issue:** [#141](https://github.com/chinmay-sawant/codehound/issues/141) (G5)  
> **Parent epic:** [#136](https://github.com/chinmay-sawant/codehound/issues/136)  
> **Gate ledger:** [`phase5-gated-work.md`](./phase5-gated-work.md) G5  
> **Prior decision:** [`taint-capability-decision.md`](./taint-capability-decision.md)  
> **Product docs:** [`documents/taint.md`](../../documents/taint.md), [ADR 0003](../../documents/adr/0003-taint-model.md)  
> **Status:** **Remain deferred** — no engine edges, no whole-program claim  
> **Date:** 2026-07-22  
> **Kind:** Ceiling evaluation + reopen FP/FN contract (docs; optional silence test only)

---

## Purpose

G5 under epic #136 covers three deferred advanced-taint capabilities. Issue #141
requires a **single** enhancement with a written FP/FN contract before any
implementation work.

This note:

1. Picks **one** ceiling for evaluation.
2. Records the **current shipped ceiling** with evidence.
3. Writes the **FP/FN contract required to reopen** that ceiling.
4. Explains **why it remains deferred** now.
5. Leaves a **reopen checklist** (no fake dataflow in this tranche).

**Non-actions (binding for this PR / evaluation):**

- No channel/goroutine assignment edges
- No external-package summary wiring
- No `(*Decoder).Decode` output-pointer expansion
- No typed Go / `go/packages` smuggling (coordinate with G4 / #140 / Gate #49)

---

## Chosen ceiling: channel / goroutine handoffs

| Field | Value |
|-------|--------|
| **Picked** | **Channel / goroutine concurrent handoffs** |
| **Not picked (still deferred, not evaluated here)** | External-package summaries; decoder receivers (`(*Decoder).Decode`) |
| **Why this one** | Strongest **explicit FN** model already in the engine (`UnsupportedFlow::{Channel,Goroutine}`); highest risk if “support” is faked with naive edges; independent of typed-facts alone (needs concurrent data-flow design). |

Sibling ceilings remain at the decisions in
[`taint-capability-decision.md`](./taint-capability-decision.md) §2–3 and are
**not** reopened by this evaluation.

---

## Current ceiling (shipped)

### Contract today

| Behavior | Shipped truth |
|----------|---------------|
| Channel send (`ch <- x`) | Recorded as `UnsupportedFlowKind::Channel` — **not** a graph assignment |
| Channel receive (`y := <-ch`, `<-ch`) | No cross-channel edge; receive is not a designed concurrent transfer |
| Goroutine spawn (`go f(...)`) | Recorded as `UnsupportedFlowKind::Goroutine` — spawn is not a taint transfer model |
| Product honesty | Prefer honest FN over pretend concurrent coverage (ADR 0003) |
| Whole-program concurrent taint | **Non-goal** for 0.1.x (`ROADMAP.md`) |

### Evidence

| Artifact | Role |
|----------|------|
| `documents/taint.md` § Limitations — Channel/goroutine | Product-facing ceiling |
| ADR 0003 | Prefer honest FNs over pretending channels work |
| `taint-capability-decision.md` §4 | Prior **defer** with FN/FP/fixture/infra assessment |
| `extract/walker_records.rs` `record_send` / `record_go_stmt` | Extractor records unsupported sites; no fake assignment edges |
| `graph_query/tests.rs` `channel_send_is_unsupported_not_assignment` | Unit: channel send is unsupported, not assignment |
| `graph_query/tests.rs` `channel_send_receive_handoff_remains_silent_fn` | Unit: classic send→receive→sink path stays silent (honest FN) |
| `CHANGELOG.md` Phase 8 | Channel/goroutine sites as explicit unsupported FNs |
| Integration `DEFERRED` empty; IP-007/IP-008 active | Recursion + closure capture are **not** the channel boundary |
| IP-010 fixtures still in corpus | Residual source-on-send attribution can still fire; **not** approved channel modeling (see below) |

### Residual IP-010 quirk (do not expand)

A **source call used as a send value** can still attribute the channel identifier
via `result_variable_of_call` for `send_statement`. Some IP-010-shaped fixtures
may therefore still emit findings. That is a residual attribution quirk, **not**
first-class channel/goroutine dataflow.

**Policy:** do not grow that quirk into “channel support.” Any future model must
**replace** it with an intentional contract + fixtures (see reopen checklist).

### Explicit non-model

```text
x := source()
ch <- x          // UnsupportedFlow::Channel — no assignment edge
y := <-ch        // no designed transfer from send site
sink(y)          // honest FN: no path through the channel
```

```text
go func() { sink(x) }()   // UnsupportedFlow::Goroutine at spawn
// Body may still be extracted for local facts; spawn is not a concurrent
// handoff model and must not invent may-happen-in-parallel edges.
```

---

## FP/FN contract required to reopen (channel / goroutine)

Reopen only with a **scoped implementable issue** (not #141 as a bulk mega-ticket,
not #121) that adopts **all** of the following as the capability contract.

### False negatives (allowed / required honesty)

| Case | Expected |
|------|----------|
| Multi-sender / multi-receiver channels without a designed alias model | May FN |
| `select` branches, default, timeout races | May FN until modeled |
| Buffered capacity / close / range-over-channel lifecycle | May FN |
| Cross-goroutine heap sharing without channel handoff | Out of scope unless separately contracted |
| Opaque interface callees inside `go` bodies | Same opacity rules as today |
| Security-grade whole-program concurrent taint | **Never claimed** under 0.1.x non-goals |

### False positives (must not ship)

| Anti-pattern | Why forbidden |
|--------------|---------------|
| Treating every `ch <- x` as `ch = x` graph assignment | Invents flows; fans out / multi-sender explode FP |
| Treating every `y := <-ch` as reading “last send” without MHP / alias rules | Invents order; high FP |
| Blind edges from all senders to all receivers in a package | Catastrophic FP on shared channels |
| Expanding residual source-on-send attribution as “support” | Undocumented, non-contractual |
| Claiming channel support in README / taint.md while only AST sugar exists | Violates ADR 0003 |

### True positives (minimum support bar if reopened)

A reopen implementation must fire on **designed** cases with fixtures, for
example:

1. **Same-function unbuffered handoff (single sender, single receiver)** where
   the contract explicitly models send→receive transfer for a proven channel
   binding (not name-string only across unrelated channels).
2. **Safe constant path:** constant (or sanitized) value sent; receive→sink must
   **not** fire.
3. **Negative:** unrelated channel `ch2` must not inherit taint from `ch1`.

Additional shapes (select, buffer, multi-goroutine) are optional stretch goals
but, if claimed in docs, need matching fixtures.

### Design constraints (no fake dataflow)

1. **No silent assignment sugar.** Channel send/receive must not become ordinary
   `AssignmentDetail` edges without a concurrent transfer record type and docs.
2. **Written model first:** channel identity, send/receive pairing rules,
   goroutine boundary, and what remains `UnsupportedFlow`.
3. **Fixtures + integration + canary** before docs claim support
   (`go_taint_integration` and/or focused unit tests; representative module).
4. **Dependency clarity:** concurrent data-flow is the primary dependency.
   Typed facts (G4) may help receiver/channel types later but **do not** by
   themselves authorize channel edges. Do not implement typed mode under a
   channel ticket.
5. **IP-010 residual:** either leave documented as quirk until replaced, or
   remove/replace in the same PR that ships the real model — no dual story.

### Fixture / test floor (reopen implementation)

| Required | Notes |
|----------|--------|
| Vulnerable + safe pair for single-channel handoff | Same CWE family as other IP fixtures (e.g. CWE-22) |
| Multi-channel non-interference negative | `ch1` taint must not poison `ch2` |
| Unit: unsupported sites still recorded where model declines | Honest residual FN inventory |
| Integration registration | No silent DEFERRED without plan note |
| Real-module / canary sanity | No mass FP spike from naive edges |

---

## Why still deferred

| Factor | Assessment |
|--------|------------|
| **FN risk if deferred** | True concurrent handoffs stay lost — **intentional** explicit FN (Phase 8 + ADR 0003). Acceptable for experimental / triage taint. |
| **FP risk if implemented naively** | **High** — fan-out, select, buffer, multi-sender, closed channels. Naive edges invent flows. |
| **Infra gap** | Needs concurrent data-flow / may-happen-in-parallel reasoning, not AST assignment sugar. |
| **Product non-goal** | Security-grade whole-program taint remains a non-goal (`ROADMAP.md`). |
| **G4 coupling** | Types alone do not solve concurrent handoffs; do not smuggle `--typed` under G5. |
| **Cost vs value** | Shipped taint already covers same-package depth-bounded inter-proc, field keys, limited decoder Unmarshal bridges, Prepare same-var. Concurrent handoffs are a large investment for triage-grade value. |

**Decision:** **remain deferred.** Keep the explicit false-negative model. Do not
schedule channel/goroutine implementation under catalog-trust or unchecked
historical plan boxes.

---

## Reopen checklist (process)

All required before any implementation PR:

- [ ] Written FP/FN contract for **channel/goroutine only** (this section adopted or amended in-issue) — not bundled with external-package + decoder in one PR unless a unified design doc exists.
- [ ] Design note that does **not** invent ordinary assignment edges for send/receive; defines transfer records and residual `UnsupportedFlow` cases.
- [ ] Vulnerable + safe fixtures (incl. multi-channel negative) + unit/integration tests.
- [ ] Representative-project / canary check (no silent mass FP).
- [ ] Dependency clarity vs G4 / Gate #49 (typed facts optional helper only; not a side-door).
- [ ] Plan to replace or explicitly quarantine IP-010 residual source-on-send attribution.
- [ ] Same-PR updates to `documents/taint.md` + capability decision (or successor ADR amendment).
- [ ] **New scoped implementable issue** (do not reopen closed #121; #141 evaluation closed by this record — use a **new** issue for implementation).

Sibling ceilings (when separately prioritized):

| Ceiling | Gate reference |
|---------|----------------|
| External-package summaries | `taint-capability-decision.md` §3 — package graph / summary infra; whole-program non-goal unless tightly scoped |
| Decoder receivers | `taint-capability-decision.md` §2 — typed or import-qualified allowlist; keep Unmarshal-only bridge until then |

---

## Explicit non-claims

This evaluation does **not**:

- implement channel, receive, or goroutine taint edges,
- approve external-package or decoder-receiver work,
- reverse ADR 0003 or the whole-program non-goal,
- treat IP-010 residual findings as channel modeling success,
- authorize G4 typed mode.

---

## Execution checklist

### Completed (2026-07-22)

- [x] Read `taint-capability-decision.md`, `documents/taint.md`, ADR 0003, G5 gate row
- [x] Pick **one** ceiling: channel/goroutine handoffs
- [x] Document current ceiling + evidence
- [x] Document FP/FN contract required to reopen
- [x] Decision: **remain deferred** with reopen checklist
- [x] Optional unit test: send→receive→sink remains silent (no invented edges)
- [x] No engine dataflow expansion beyond documenting silence
- [x] Cross-link #141 / #136

### Remaining to reopen implementation (channel/goroutine)

- [ ] Written FP/FN contract accepted for concurrent handoffs
- [ ] Design that does not invent naive send/receive edges
- [ ] Fixtures + integration tests + canary
- [ ] Dependency clarity vs G4 typed facts if required
- [ ] New scoped implementable issue (not #141 alone as delivery)

### Deferred siblings (still not this plan)

- [ ] External-package taint summaries
- [ ] Decoder-receiver output bridges

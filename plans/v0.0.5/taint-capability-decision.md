# v0.0.5 — Advanced Taint Capability Decision Record

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 4.3  
> **Issue:** [#40](https://github.com/chinmay-sawant/codehound/issues/40) Phase 4.3  
> **Status:** Decision record only — **no engine rewrite** in this tranche.  
> **Related:** `documents/taint.md`, [ADR 0003](../../documents/adr/0003-taint-model.md), `ROADMAP.md` (non-goal: security-grade whole-program taint), `tests/go_taint_integration.rs`

---

## Purpose

Decide which advanced taint enhancements justify design work (and later
implementation under a separate issue) versus remaining explicit capability
ceilings. This document is **not** an implementation plan and does **not**
claim whole-program taint coverage.

Product bar remains ADR 0003: prefer **honest false negatives** over pretending
unsupported flows work. Taint stays experimental / triage-grade.

---

## Current ceiling (shipped contract)

Evidence as of branch `chore/pending-items-2` / Phase 8 taint depth:

| Area | Shipped behavior | Evidence |
|------|------------------|----------|
| Intra-proc graph | Versioned last-write, field-qualified keys, map/slice base taint | `documents/taint.md` § Intra-proc precision |
| Inter-proc | Depth-bounded summaries (`--taint-depth` 1–4), not a full fixpoint | `documents/taint.md`, `graph_query/summary.rs` |
| CWE-89 “safe” SQL | **Literal first arg** at Query/Exec only (`is_parameterized_query`) | `taint/rules/cwe_89.rs` |
| Bare `.Prepare` | **Not** a sanitizer (dynamic Prepare still injectable) | `extract/classify.rs` comment; `documents/taint.md` |
| Decoder outputs | Pointer bridge for `json.Unmarshal` / `xml.Unmarshal` only | `graph_query/build.rs` `tainted_output_args` |
| External packages | Import map extracted; cross-package summary wiring deferred | `extract/imports.rs` ponytail |
| Channel / goroutine | Sites recorded as `UnsupportedFlow::{Channel,Goroutine}` — **explicit FN** | `walker_records.rs`, CHANGELOG Phase 8, unit test `channel_send_is_unsupported_not_assignment` |
| Integration suite | All registered IP fixtures run; `DEFERRED` is empty | `tests/go_taint_integration.rs` |
| IP-007 / IP-008 | **Active** recursion + closure capture — **not** the channel/goroutine boundary | fixtures under `tests/fixtures/go/taint/` |
| IP-010 | Goroutine+channel shape still in corpus; residual source-on-send attribution can fire CWE-22 while full channel modeling is unsupported | fixture + scan evidence (`variable: "ch"`); Phase 8 docs override older “channel edges” plans |

**Explicit false-negative model (keep):** unsupported constructs do not get fake
assignment edges that pretend full concurrency/package/type analysis exists.
Documented ceilings stay in `documents/taint.md`. New behavior only after a
written FP/FN contract, fixtures, integration tests, and representative-project
canaries.

**Non-goal (reaffirmed):** security-grade whole-program taint (`ROADMAP.md`).

---

## Decision table

| Enhancement | Decision | Typed facts / stronger DF needed? |
|-------------|----------|-----------------------------------|
| Prepared-statement same-var parameterization | **Approve design** | No (same-function AST binding first) |
| Decoder output pointers (`(*Decoder).Decode`) | **Defer** | Yes for trustworthy receiver typing |
| External-package propagation | **Defer** | Yes (summaries / package graph) |
| Channel / goroutine handoffs | **Defer** | Yes (concurrent data-flow) |

---

## 1. Prepared-statement same-variable parameterization

### Proposal

Recognize a conservative same-function pattern:

```go
stmt, err := db.Prepare("SELECT … WHERE id = ?") // literal SQL
// …
rows, err := stmt.Query(userId) // or stmt.Exec
```

When the **same binding** of `*sql.Stmt` (or equivalent) is proven to come from
`Prepare`/`PrepareContext` with a **literal** query string, treat the
`Stmt.Query`/`Exec` path as parameterized for CWE-89 — without treating bare
`.Prepare` as a global sanitizer.

### Decision: **approve design**

Rationale:

| Factor | Assessment |
|--------|------------|
| **FN risk (if deferred forever)** | Safe Prepare→Stmt.Query code keeps firing CWE-89 (noise / FP for users). |
| **FP risk (if implemented naively)** | High if bare `.Prepare` or dynamic SQL strings suppress findings. Dynamic `Prepare(fmt.Sprintf(...))` must still fire. |
| **FP risk (approved design)** | Low if limited to same-function same-var + literal Prepare SQL + no rebind. |
| **Fixture cost** | Medium: vulnerable (dynamic Prepare; string-concat Query; reassigned stmt), safe (literal Prepare + Stmt.Query/Exec), renamed imports, PrepareContext. |
| **Infra** | Does **not** require typed Go facts or whole-program analysis for the first cut. |

### Approved design sketch (implementation **not** in this tranche)

1. **Do not** add bare `.Prepare` to `classify_sanitizer` / `SanitizerKind::SQL` without the same-var proof.
2. Prefer a **sink-side guard** (extend or sit beside `is_parameterized_query`): at `stmt.Query`/`Exec`, resolve receiver binding to a prior `Prepare`/`PrepareContext` in the same function with literal first arg and no intervening reassignment of that receiver.
3. Inter-function Prepare factories stay out of scope until a summary contract exists.
4. Ship only with:
   - vulnerable + safe fixtures (incl. dynamic Prepare FN/FP pair),
   - `go_taint_integration` (or CWE-89 taint) coverage,
   - a small real-module canary (no mass CWE-89 silence).
5. Update `documents/taint.md` in the same PR as any code change.

### Gate before code

Keep the current explicit FN/heuristic model until the design above has fixtures +
integration tests + canaries. No implementation under this decision-record-only
tranche.

---

## 2. Decoder output pointers

### Proposal

Extend the `json.Unmarshal` / `xml.Unmarshal` output-pointer bridge to
receiver forms such as `decoder.Decode(&target)` / `DecodeElement`.

### Decision: **defer**

Rationale:

| Factor | Assessment |
|--------|------------|
| **FN risk** | Real json/xml/gob decode→sink flows miss when only `*.Decode` is used (honest FN today). |
| **FP risk if name-only** | High: many `Decode` methods (gob, json, xml, custom). Without types, tainting every `*.Decode` output is noisy. |
| **Fixture cost** | Medium–high: multi-decoder packages, safe/vuln pairs, interface-typed receivers. |
| **Infra** | Trustworthy coverage wants type/receiver facts (`--typed` / `go/packages`) or a carefully allowlisted import+selector table; both exceed Phase 4.3 docs-only scope. |

**Keep:** `tainted_output_args` for `json.Unmarshal` / `xml.Unmarshal` only
(`build.rs` ponytail remains accurate). Revisit only with typed facts or a
narrow import-qualified allowlist design issue — not under catalog-trust work.

---

## 3. External-package propagation

### Proposal

Wire `build_import_map` into cross-function analysis so callees in other
packages propagate taint (or apply known summaries) instead of staying opaque.

### Decision: **defer**

Rationale:

| Factor | Assessment |
|--------|------------|
| **FN risk** | Wrapper packages / helpers in other modules lose taint at the boundary (honest FN). |
| **FP risk** | High without accurate summaries: treating unknown external returns as always-tainted floods; treating them as always-clean hides sinks. |
| **Fixture cost** | High: multi-module trees, versioned deps, method sets, interfaces. |
| **Infra** | Approaches whole-program / multi-package summary infrastructure. **Contradicts** the 0.1.x non-goal of security-grade whole-program taint unless tightly scoped (stdlib allowlist only). |

**Keep:** same-package / depth-bounded inter-proc only; external callees remain
opaque (args may carry taint; returns generally not summarized). Import map may
stay as a future hook; no claim of external-package completeness.

---

## 4. Channel / goroutine handoffs

### Proposal

Model `ch <- x` / `<-ch` and `go f(...)` so taint crosses concurrent handoffs
(full IP-010-style channel flows as a first-class, intentional model).

### Decision: **defer**

Rationale:

| Factor | Assessment |
|--------|------------|
| **FN risk** | True concurrent handoffs are lost — **intentional** explicit FN (Phase 8). |
| **FP risk if fake edges** | High: fan-out, select, buffered channels, closed channels, multi-sender — naive edges invent flows. |
| **Fixture cost** | High: send/receive, select, buffered, multi-goroutine, safe constant paths, safe/vuln pairs. |
| **Infra** | Needs concurrent data-flow / may-happen-in-parallel reasoning, not AST assignment sugar. |

**Keep current explicit FN model:**

- Extractor records `UnsupportedFlow::{Channel,Goroutine}` and does **not**
  treat channel send as a normal graph assignment (`walker_records.rs`, unit
  test in `graph_query/tests.rs`).
- Product docs state channel/goroutine unsupported (`documents/taint.md`, ADR 0003).
- Historical plans that claim full channel assignment edges
  (`plans/v0.0.2/p1f-phase6-edge-cases.md` §6.5) are **superseded** by Phase 8.
- Note residual behavior: a **source call used as a send value** can still
  attribute the channel identifier via `result_variable_of_call` for
  `send_statement`, so some IP-010-shaped fixtures may still fire. That is a
  residual attribution quirk, **not** approved channel modeling. Do not expand
  it; any future model must replace this with a designed contract + fixtures.

**Clarify inventory (Phase 0 correction):** IP-007 = recursive chain, IP-008 =
closure capture — both **supported** and integration-tested. Channel/goroutine
is the unsupported **boundary**, not a deferred IP-007/IP-008 gap.

---

## Cross-cutting policy (binding)

1. **Keep the explicit false-negative model** until any new contract has:
   - written FP/FN rules in this style (or an ADR amendment),
   - vulnerable + safe fixtures,
   - integration tests (`go_taint_integration` and/or focused unit tests),
   - representative-project / canary validation (no silent mass FP drop).
2. **Do not claim whole-program taint coverage** in README, ROADMAP, marketing,
   or `documents/taint.md`.
3. **Prefer docs honesty over silent “support”.** If a flow is unsupported,
   record it (as today) rather than inventing edges.
4. **Implementation gate:** none of the four enhancements ship code under this
   decision record alone. **Approve design** items need a separate issue before
   engine work. **Defer** items need a future decision revisit (typically after
   typed facts or a funded data-flow investment).
5. **ADR 0003 still owns honesty:** experimental / triage; not a sole security
   gate.

---

## Does this justify typed Go facts now?

| Enhancement | Alone justifies `--typed` / go/packages? |
|-------------|------------------------------------------|
| Prepare same-var | No |
| Decoder.Decode | Partially (receiver type) — still **defer** the feature |
| External packages | Yes for serious coverage — still **defer** the feature and typed investment together |
| Channel/goroutine | Concurrent DF > types alone — still **defer** |

**Conclusion:** Phase 4.3 does **not** unlock typed Go facts or a taint engine
rewrite. Typed facts remain roadmap “Later” (`ROADMAP.md` / Phase 4.4). Only
the Prepare same-var design is approved as a future **narrow AST** improvement
candidate.

---

## Explicit non-claims

This record does **not**:

- implement or schedule engine changes,
- expand sanitizer tables,
- enable channel edges,
- promise external-package or multi-module taint,
- reverse ADR 0003 or the whole-program non-goal.

---

## Follow-ups (out of band)

| Item | Owner signal |
|------|----------------|
| Optional issue: “CWE-89 same-var Prepare→Stmt parameterization (design-approved)” | Only if product prioritizes CWE-89 precision |
| Keep IP-010 / channel residual behavior documented if docs drift | On next `documents/taint.md` touch |
| Typed facts / external summaries / concurrent DF | Decision-gated later; not under #39 catalog trust |

---

## Verification (decision-record scope)

- [x] Ceilings cross-checked against `documents/taint.md`, ADR 0003, Phase 8 CHANGELOG, extractor/graph code, and `tests/go_taint_integration.rs`.
- [x] IP-007/IP-008 identity corrected (recursion/closure, not channel deferral).
- [x] Four proposals decided with FN/FP + fixture cost.
- [x] Explicit FN model retained until fixtures + integration + canaries.
- [x] No whole-program coverage claim.
- [x] No edits to `pending-work.md`; no commit required for this deliverable.

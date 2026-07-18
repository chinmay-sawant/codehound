# v0.0.5 — Phase 4.4: Roadmap-only investments (decision record)

> **Parent:** `plans/v0.0.5/pending-work.md` §4.4; GitHub issue [#40](https://github.com/chinmay-sawant/codehound/issues/40)  
> **Status:** **Deferred** (both investments). Docs-only disposition; no implementation.  
> **Date:** 2026-07-18  
> **Decision owner:** product / roadmap (not #39 CWE tranche)

---

## Scope

Record an explicit **defer** for two ROADMAP “Later” rows that must not be started from unchecked historical boxes or under catalog-trust issues:

1. Optional typed Go facts (`--typed` / `go/packages`)
2. Python language investment (beyond experimental `SLOP101`)

This document does **not** implement either investment, change feature flags, or reverse ADR 0005.

---

## 1. Optional `--typed` / `go/packages` — **defer**

### Decision

**Defer.** Do not design, ship, or prototype optional typed Go analysis via `go/packages` + `go/types` in 0.1.x under Phase 4.4 / issue #40.

### Source-of-truth statements

| Source | Statement |
|--------|-----------|
| [`ROADMAP.md`](../../ROADMAP.md) — Next | “**Typed Go facts** — Optional `--typed` / go/packages **only if PERF pack trusted**” |
| [`plans/feedback/10072026/go.md`](../feedback/10072026/go.md) §18 | Hybrid `go/packages` is a **big bet**; stay tree-sitter-only for speed/offline; typed mode needs Go toolchain, is slower/complex. **Do not block 0.1.0** on typed mode; design detector APIs so a later typed fact layer can feed the same rules. |
| [`plans/feedback/10072026/action-items.md`](../feedback/10072026/action-items.md) §8.3 | Optional hybrid `go/packages` — **do not block 0.1.0**; “**Deferred as product milestone until PERF pack trusted**” |
| [`plans/v0.0.5/pending-work.md`](./pending-work.md) §4.4 | “Consider optional `--typed` / `go/packages` support **only after the PERF pack is trusted**.” |
| [`ROADMAP.md`](../../ROADMAP.md) — Non-goals | Security-grade whole-program taint remains a non-goal for 0.1.x (typed facts would not change that claim boundary without a separate taint contract). |

### Current PERF / recommended trust evidence (why “until pack trusted” is still the gate)

Typed mode is gated on **PERF pack trust**, not on “any open checkbox.” Current evidence is strong for the **recommended** CI gate and for full-catalog noise hygiene, but does not authorize a toolchain-dependent typed layer:

| Evidence | Result | Path |
|----------|--------|------|
| **noise-reduce-1 closed** | Pinned `real-repos/gorl` full-catalog canary **53** findings (23 example-tagged, 30 non-example); **recommended remains 0**. Plan status: **Closed** for that checklist; further detector batches need a new issue. | [`plans/v0.0.5/noise-reduce-1.md`](./noise-reduce-1.md); PR [#38](https://github.com/chinmay-sawant/codehound/pull/38) |
| **Recommended-pack pilot** | Senior-reviewed sample of 20 recommended findings on real repos: **19 / 20 = 95.0%** actionable (bar was 70%). Post-fix full recommended set across three repos: **40 / 41 = 97.6%** actionable. | [`plans/v0.0.5/pending-work.md`](./pending-work.md) §3.1; also summarized in [`ROADMAP.md`](../../ROADMAP.md) Current |
| **ROADMAP Current** | Trust evidence line: recommended-pack pilot reviewed 20 real findings (95% actionable); cold-scan / BP canaries closed. | [`ROADMAP.md`](../../ROADMAP.md) |

**Interpretation:** Recommended-pack product trust and noise-reduce-1 closure establish that tree-sitter PERF/BP defaults are the right investment surface. They do **not** satisfy a “PERF pack trusted enough to justify optional `go/packages`” product milestone by themselves: typed mode adds toolchain dependency, slower scans, and a second fact pipeline. Remaining full-catalog noise, long-tail CWE trust ([#39](https://github.com/chinmay-sawant/codehound/issues/39)), and explicit taint FN boundaries (§4.3) should be resolved or explicitly accepted **before** typed mode is considered.

### Preconditions for reconsideration

Reopen only with a **scoped GitHub issue** (not under #39 or bulk historical checkboxes) when **all** of the following hold:

1. **PERF pack trust bar (product):** Documented acceptance that S-tier / recommended PERF (and any broader PERF profile under consideration) meets an agreed external FP rate on pinned real modules—not only the 20-finding pilot—e.g. sustained recommended zero/false-positive policy on canaries plus senior disposition of residual full-catalog PERF noise.
2. **Catalog honesty:** CWE long-tail / NEEDLES work under [#39](https://github.com/chinmay-sawant/codehound/issues/39) has either closed the relevant trust gaps or recorded explicit keep/quarantine decisions that typed facts would not be asked to paper over.
3. **Capability contract:** Written FN/FP contract for what typed facts improve (e.g. receiver types, build tags, same-package signatures) vs. what remains unsupported (channel/goroutine handoffs, whole-program taint — see ROADMAP non-goals and pending-work §4.3).
4. **Architecture sketch:** Detector APIs stay tree-sitter-primary; typed facts are an **optional** layer feeding the same rules (per go.md §18), with offline/no-toolchain default preserved.
5. **Cost acceptance:** Measured impact of requiring a Go toolchain for `--typed`, scan latency/memory vs. tree-sitter-only, and CI matrix implications.
6. **Non-blocker policy retained:** Typed mode must not become a release or recommended-pack dependency.

Until those preconditions are met, leave ROADMAP “Typed Go facts” in **Later** and keep implementation unchecked.

---

## 2. Python investment — **defer**

### Decision

**Defer.** Do not fund, design, or implement a multi-rule Python catalog (or marketing multi-lang parity) in 0.1.x. Python remains experimental opt-in only (`--features python`, single rule `SLOP101`), consistent with the accepted Go-first demote.

### Source-of-truth statements

| Source | Statement |
|--------|-----------|
| [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md) | **Option B — Demote (Go-first)** accepted (Phase 9). Python is **one rule** (`SLOP101`), proof-of-life only; **opt-in** feature, not in `default`. **Do not** invest in 10–20 Python rules in 0.1.x unless product demand is **funded later** (**revisit as a new ADR**). Non-goal: claiming multi-language SAST parity. |
| [`ROADMAP.md`](../../ROADMAP.md) — Next | “**Python invest** — Only if funded — **reverse ADR 0005 demote with a new ADR**” |
| [`ROADMAP.md`](../../ROADMAP.md) — Multi-lang decision | Demote / Go-first per ADR 0005: default features exclude Python; TypeScript stub removed; marketing matches Go production capability. |
| [`plans/feedback/10072026/action-items.md`](../feedback/10072026/action-items.md) §9.1 | **Option A — Invest:** rejected for 0.1.x (**revisit only with funding + new ADR**). **Option B — Demote:** done. |
| [`plans/v0.0.5/pending-work.md`](./pending-work.md) §4.4 | “Consider Python investment only with **explicit funding** and a **new/reversed ADR**, as required by the Go-first multi-language decision.” |

### What would be required to reverse the deferral

A future invest decision is **out of scope** for #40. Minimum requirements before any implementation:

1. **Funding / product demand:** Explicit, time-bounded product commitment (issue + owner + success metrics)—not a residual plan checkbox.
2. **New or reversing ADR:** Supersede or amend ADR 0005 with a written invest decision (catalog size, severity of claim, default vs. opt-in features, marketing language). Demote remains in force until that ADR is accepted.
3. **Honesty bar:** README / ROADMAP / frontend / schema updated only after capability matches claim (ADR 0005 consequence: marketing matches capability).
4. **Engineering floor for a real second language** (illustrative checklist, not a commitment):
   - Language plugin with production detectors (not a single proof-of-life rule)
   - Fixtures, integration tests, and canary corpus on real Python modules
   - Pack/profile story (recommended vs. experimental)
   - CI matrix for `--features python` as a supported surface, not a stub cell
   - Incremental cache / dependency extraction / ignore semantics already partially present must be productized and measured
5. **Non-goals retained unless separately decided:** Runtime-loadable language plugins remain a permanent non-goal (ADR 0005); multi-language SAST parity is not claimed by adding a second language alone.

Until funding + new/reversed ADR exist, leave ROADMAP “Python invest” in **Later** and keep Python off default features.

---

## Explicit non-actions (this decision)

- No `--typed` CLI flag, no `go/packages` integration, no typed fact layer design spike as delivery under #40.
- No Python rule expansion, no re-adding TypeScript stubs, no default-feature change for Python.
- No edit required to ADR 0005 text (still Accepted); this record **reaffirms** it.
- Implementation work continues under existing gates (e.g. CWE trust [#39](https://github.com/chinmay-sawant/codehound/issues/39)), not under these deferred investments.

---

## Summary table

| Investment | Disposition | Gate to reopen | Primary evidence |
|------------|-------------|----------------|------------------|
| `--typed` / `go/packages` | **Defer** | PERF pack trust + capability/cost contract + scoped issue | ROADMAP Next; go.md §18; action-items §8.3; noise-reduce-1 closed; recommended pilot 95% |
| Python multi-rule invest | **Defer** | Funding + new/reversed ADR | ADR 0005; ROADMAP Next + Phase 9; action-items §9.1 |

---

## Related

- Parent ledger: [`plans/v0.0.5/pending-work.md`](./pending-work.md) Phase 4.4  
- Issue: [#40](https://github.com/chinmay-sawant/codehound/issues/40)  
- ADR: [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md)  
- Roadmap: [`ROADMAP.md`](../../ROADMAP.md)  
- PERF noise canary: [`plans/v0.0.5/noise-reduce-1.md`](./noise-reduce-1.md)  
- Recommended pilot: [`plans/v0.0.5/pending-work.md`](./pending-work.md) §3.1  

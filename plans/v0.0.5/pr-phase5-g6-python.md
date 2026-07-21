# docs(phase5): G6 Python catalog gate evaluation (remain deferred)

## Summary

Docs-only evaluation of **Gate B1–B4** for Phase 5 **G6** (Python multi-rule catalog investment). Inventories current Python capability honestly (**SLOP101** only), scores reopen criteria, records demand status and the ADR path, and **reaffirms defer** under ADR 0005 Go-first.

**Closes #142 · Relates to #136**

**No product code, no new Python rules, no Cargo default changes, no ADR 0005 reverse.**

---

## Motivation / context

- Parent epic: [#136](https://github.com/chinmay-sawant/codehound/issues/136)
- Child: [#142](https://github.com/chinmay-sawant/codehound/issues/142) — gated(G6): Python catalog investment
- Gate criteria: [`roadmap-gates-49.md`](./roadmap-gates-49.md) Gate B · prior defer [`roadmap-investments-decision.md`](./roadmap-investments-decision.md) §2
- ADR: [`documents/adr/0005-multi-lang-honesty.md`](../../documents/adr/0005-multi-lang-honesty.md) (Accepted demote)
- Ledger: [`phase5-gated-work.md`](./phase5-gated-work.md) § G6
- Branch: `docs/phase5-g6-python-gate`
- Base: `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`

G6 must not be scheduled as an ordinary catalog slice. This PR freezes an explicit pass/fail evaluation so residual checkboxes do not authorize multi-rule Python work.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-g6-python-gate-eval.md` | Inventory, B1–B4 pass/fail, demand status, ADR path, decision **remain deferred** |
| `plans/v0.0.5/pr-phase5-g6-python.md` | This PR body |

---

## Gate B summary

| # | Criterion | Result |
|---|-----------|--------|
| **B1** | Funded / time-bounded product demand (owner + metrics) | **Fail** |
| **B2** | New or reversing ADR Accepted (amend/supersede 0005) | **Fail** — ADR 0005 still Accepted demote |
| **B3** | Honesty bar after capability matches invest claim | **N/A** until B1–B2 (current docs match proof-of-life demote) |
| **B4** | Engineering floor (production detectors, real canaries, packs, CI product surface) | **Fail** — SLOP101 + two fixtures only |

**Decision: remain deferred.** Python stays opt-in experimental (`--features python`, single rule).

### Current capability (honest)

- Plugin: `src/lang/python/` — 4 Rust files
- Rules: **SLOP101** only (`ReCompileInLoop`)
- Fixtures: `tests/fixtures/python/{sample,safe}.txt`
- Tests: feature-gated `tests/python_integration.rs`
- No Python PERF/CWE/BP/taint packs; no real-module Python canary

---

## Out of scope (explicit)

- Any new Python detector or multi-rule catalog
- Reversing or amending ADR 0005 text in this PR
- Changing Cargo `default` / CI product claims
- Re-adding TypeScript stubs
- Marketing multi-language SAST parity
- Implementing G1–G5

---

## How to reopen later

1. Funded demand record (B1) with owner + metrics.
2. Accepted invest/reverse ADR (B2).
3. Ship capability then honesty updates (B3) and engineering floor (B4).
4. Implement under #142 (or a new scoped child) — not as a drive-by under closed #49 / #40 / #121.

Full path: [`phase5-g6-python-gate-eval.md`](./phase5-g6-python-gate-eval.md) § ADR path.

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | None |
| **API / CLI** | None |
| **Tests / canary** | N/A (docs only) |
| **Packs / maturity** | Unchanged |
| **ADR 0005** | Reaffirmed demote |

---

## Test plan

- [x] Docs-only; no `cargo test` required for product behavior
- [x] Review eval against `roadmap-gates-49.md` Gate B and ADR 0005
- [x] Confirm no `src/lang/python` rule additions in the diff

# v0.0.6 — G6 Python multi-rule catalog

> **Class:** A (gated)  
> **Issue:** [#157](https://github.com/chinmay-sawant/codehound/issues/157) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g6-python-gate-eval.md`](../v0.0.5/phase5-g6-python-gate-eval.md)  
> **Gate B refresh:** [`evidence-g6-gate-b.md`](./evidence-g6-gate-b.md) (2026-07-23)  
> **Status:** Deferred — SLOP101 only; ADR 0005 Go-first · Gate B **FAIL** (B1/B2/B4)

## Checklist

### Gate B (all required)
- [ ] B1 Funded demand + owner + metrics — **FAIL** 2026-07-23 ([evidence](./evidence-g6-gate-b.md))
- [ ] B2 New/reverse ADR Accepted — **FAIL** 2026-07-23 (ADR 0005 still demote; no invest ADR)
- [ ] B3 Honesty bar for product claims — **N/A** until B1–B2 (demote honesty OK)
- [ ] B4 Engineering floor for multi-rule language — **FAIL** 2026-07-23 (SLOP101 + synthetic fixtures only)

### Implementation (after Gate B)
- [ ] Multi-rule Python pack with fixtures
- [ ] Docs honesty matches capability
- [ ] Tests / canary as claimed

### Explicit non-goals
- [x] No multi-rule Python without ADR
- [x] No marketing claims beyond proof-of-life demote
- [x] No new Python detectors / Cargo default flip in Gate B refresh (2026-07-23)

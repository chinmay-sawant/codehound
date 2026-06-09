# P2 Implementation Plans

Detailed implementation plans for all unimplemented items from `plans/p2.md` (Production-Grade Features v1.0 Gap).

Root: `plans/p2.md`

---

## P2 Core Features (5 plans)

| # | Plan | File | Effort |
|---|------|------|--------|
| P2.1 | Taint Tracking / Data Flow Analysis | [`01-taint-tracking.md`](./01-taint-tracking.md) | 8-12 weeks |
| P2.2 | Baseline / Ignore-Once Mechanism | [`02-baseline-ignore.md`](./02-baseline-ignore.md) | 1-2 weeks |
| P2.3 | Incremental Analysis | [`03-incremental-analysis.md`](./03-incremental-analysis.md) | 2-3 weeks |
| P2.4 | PERF Ruleset Detector Implementation | [`04-perf-detector-implementation.md`](./04-perf-detector-implementation.md) | 6-8 weeks |
| P2.5 | Bad Practices Detection (Scope & Design) | [`05-bad-practices-detection.md`](./05-bad-practices-detection.md) | 1-2 weeks |

## Missing Architecture Items (5 plans)

| # | Plan | File | Effort |
|---|------|------|--------|
| A | Source Cache Population | [`missing-A-source-cache-population.md`](./missing-A-source-cache-population.md) | 3-5 days |
| B | Structured Finding Identity | [`missing-B-structured-finding-identity.md`](./missing-B-structured-finding-identity.md) | 3-5 days |
| C | Detector Output Model Evolution | [`missing-C-detector-output-model.md`](./missing-C-detector-output-model.md) | 1-2 weeks |
| D | Rule-Pack Extensibility | [`missing-D-rule-pack-extensibility.md`](./missing-D-rule-pack-extensibility.md) | design only |
| E | Observability / Diagnostic Instrumentation | [`missing-E-observability-instrumentation.md`](./missing-E-observability-instrumentation.md) | 1-2 weeks |

## Recommended Implementation Order

1. **P2.2 Baseline/Ignore** — Lowest effort, highest ROI, unblocks adoption
2. **Missing B Structured Finding Identity** — Foundation for baseline + cache + CI diffing
3. **Missing A Source Cache** — Feeds into incremental and export optimization
4. **P2.3 Incremental Analysis** — CI performance, makes everything else faster
5. **Missing E Observability** — Needed to debug incremental + taint performance
6. **Missing C Detector Output Model** — Foundation for richer findings pre-taint
7. **P2.1 Taint Tracking** — Phase 1 (intra-procedural) only; defer inter-procedural
8. **P2.4 PERF Detectors** — Batch by category, low-hanging fruit first
9. **Missing D Rule-Pack Extensibility** — Defer implementation, execute design
10. **P2.5 Bad Practices** — Complete scope/design, defer implementation

# docs(trust): recommended-pack pilot and stop-the-line (4.3)

## Summary

Document the repeatable recommended-pack pilot procedure, re-run it on the pinned corpus after Phase 2 catalog integration, record stop-the-line policy for material FP regressions, and reaffirm that the release cold-scan budget remains under threshold (no perf rewrites).

Closes #119 · Relates to #105

---

## Motivation / context

- Plan: [`plans/v0.0.5/parallel-catalog-program.md`](./parallel-catalog-program.md) §4.3
- Evidence: [`plans/v0.0.5/recommended-pack-pilot.md`](./recommended-pack-pilot.md)
- Prior Phase 3 pilot: [`plans/v0.0.5/pending-work.md`](./pending-work.md) §3.1
- Cold-scan budget: [`plans/v0.0.5/perf-budget-48.md`](./perf-budget-48.md)
- Base SHA: `7d912d5be8528f80df0122259d24130c6f394df9`

§4.1 expanded formal corpus pins are not complete; this pilot uses the established core three (gopdfsuit, monsoon, go-retry) plus opportunistic `real-repos/*` (gorl, no-mistakes).

---

## Changes

### Docs only

- **`plans/v0.0.5/recommended-pack-pilot.md`** — procedure, rubric, stop-the-line policy, cold-scan hold, 2026-07-21 results
- **`plans/v0.0.5/parallel-catalog-program.md`** — §4.3 checkboxes closed with link to pilot doc
- **`plans/v0.0.5/pr-recommended-pack-trust.md`** — this PR body

### Code

None. No detector, profile, or pack membership changes.

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | None |
| **Recommended pack trust** | Re-validated post Phase 2: core multiset unchanged; 19/20 sample still 95% actionable |
| **Performance** | Cold-scan still under budget; rewrites held |
| **API / CLI** | None |

### Pilot snapshot (release binary, recommended, no-cache)

| Repository | Findings | Notes |
|---|---:|---|
| gopdfsuit | **38** | PERF-1 ×38 (matches post-PERF-7 pilot) |
| monsoon | **3** | PERF-1, PERF-7, PERF-190 |
| go-retry | **0** | clean |
| gorl | **0** | recommended control |
| no-mistakes | **2** | PERF-189 lexical FP; PERF-7 defer+return (not stop-the-line) |

**Stop-the-line:** not triggered.  
**Cold-scan (gopdfsuit, profile all):** steady ~0.52–0.85s, **915** findings — **UNDER BUDGET**.

---

## Breaking changes / migration

None.

---

## Test plan

- [x] Release binary recommended scans on core three + real-repos extras
- [x] Cold-scan steady-state reaffirmation (4 runs)
- [x] Compared multiset to 2026-07-18 pilot
- [ ] CI docs-only / no compile required beyond existing gates if enforced

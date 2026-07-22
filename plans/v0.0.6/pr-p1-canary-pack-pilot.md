# chore(trust): P1 canary corpus re-run + recommended-pack pilot

## Summary

- Re-run the expanded decision-quality canary and recommended-pack pilot after epic #151 Class B residuals (R1–R8 / PRs #171 + #176).
- Record reviewed hit rates; confirm **no recommended-pack FP regression** and **cold-scan budget still under 1.0s**.
- Docs-only — no detector, maturity, or pack membership changes.

---

## Motivation / context

Process stream **P1** of issue [#166](https://github.com/chinmay-sawant/codehound/issues/166). Relates to epic [#151](https://github.com/chinmay-sawant/codehound/issues/151).

Procedure: [`../v0.0.5/canary-corpus.md`](../v0.0.5/canary-corpus.md), [`../v0.0.5/recommended-pack-pilot.md`](../v0.0.5/recommended-pack-pilot.md).

**Binary SHA:** `f3eaaf8a28a79fc53d4ca78acbd448294e0aeab8`  
**Branch:** `chore/p1-canary-pack-pilot`

---

## Changes

| Path | Change |
|------|--------|
| `plans/v0.0.5/canary-hit-rates.md` | Append 2026-07-23 P1 section (recommended + FO `--only` + Heuristic keep) |
| `plans/v0.0.5/recommended-pack-pilot.md` | Append §6 pilot results + cold-scan budget |
| `plans/v0.0.6/process-canary-and-pack-pilot.md` | Checklist `[x]` + summary |
| `plans/v0.0.6/pending-work.md` | Mark #166 done |

---

## Pilot results

### Recommended (`--profile recommended`)

| Repository | Files | Findings |
|------------|------:|---------:|
| gopdfsuit | 78 | 38 (PERF-1) |
| monsoon | 43 | 3 (PERF-1, PERF-7, PERF-190) |
| go-retry | 5 | 0 |
| gorl | 28 | 0 |
| no-mistakes | 222 | 2 (PERF-189, PERF-7) |

Core three multiset **unchanged** vs 2026-07-21. Stop-the-line **not** triggered. Senior 20-row sample still **95%** actionable.

### Family `--only` (separate from recommended)

| Slice | Findings / files |
|-------|-----------------:|
| R1–R8 FO quarantine set | **0 / 376** |
| CWE-201, CWE-213 (Heuristic keep) | **0 / 376** |

### Cold-scan budget (gopdfsuit `--profile all --no-cache`)

915 findings; wall ~0.50–0.87s — **UNDER BUDGET — hold performance rewrites.**

---

## Impact

| Area | Impact |
|------|--------|
| Detectors / packs | None |
| Maturity | None |
| Product trust | Confirmed recommended pack stable after FO quarantine batch |

---

## Test plan

- [x] `cargo build --release --locked`
- [x] `scripts/canary/run_decision_corpus.sh recommended`
- [x] Family `--only` FO set + CWE-201/213
- [x] Cold gopdfsuit `--profile all` ×3
- [x] Docs appended; checklist complete

---

## Related issues

Closes #166 · Relates to #151

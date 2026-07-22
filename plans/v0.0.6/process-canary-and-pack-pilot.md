# v0.0.6 — P1 Canary corpus re-run + recommended-pack pilot

> **Class:** C (process)  
> **Issue:** [#166](https://github.com/chinmay-sawant/codehound/issues/166) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Prior:** [`../v0.0.5/canary-corpus.md`](../v0.0.5/canary-corpus.md), [`../v0.0.5/recommended-pack-pilot.md`](../v0.0.5/recommended-pack-pilot.md)
> **Status:** Complete 2026-07-23 — branch `chore/p1-canary-pack-pilot` @ `f3eaaf8` binary

## Checklist
- [x] After each integrated catalog residual batch, re-run expanded canary
- [x] Run recommended profile separately from `--only` families
- [x] Append hit-rates to `canary-hit-rates.md` with review rubric
- [x] Recommended-pack pilot; stop-the-line on material FP family regressions
- [x] Note cold-scan budget (hold rewrites unless breached)

## Results (summary)

| Check | Result |
|-------|--------|
| Recommended (5 pins) | **41** core + 2 extended — **identical** to 2026-07-21 pilot |
| Stop-the-line | **Not triggered** |
| R1–R8 FO `--only` | **0 / 376** |
| CWE-201/213 Heuristic `--only` | **0 / 376** |
| Cold gopdfsuit `--profile all` | 915 findings; wall ~0.50–0.87s — **under budget** |

Details: [`../v0.0.5/canary-hit-rates.md`](../v0.0.5/canary-hit-rates.md) §2026-07-23 · [`../v0.0.5/recommended-pack-pilot.md`](../v0.0.5/recommended-pack-pilot.md) §6

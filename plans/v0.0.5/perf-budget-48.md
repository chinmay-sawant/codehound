# Issue #48 — Cold-scan budget reaffirmation

> **Issue:** [#48](https://github.com/chinmay-sawant/codehound/issues/48) Engine perf: re-evaluate only if cold-scan budget is breached  
> **Parent epic:** [#44](https://github.com/chinmay-sawant/codehound/issues/44)  
> **Branch:** `chore/perf-budget-48`  
> **Date:** 2026-07-19  
> **Binary:** `target/release/codehound` (release; built on this branch from `origin/master`)  
> **Prior decision:** `plans/v0.0.5/perf-eval-decision.md` (#40 / Phase 4.2)  
> **Code changes:** none (docs-only reaffirmation)

---

## 1. Budget (reaffirmed)

| Item | Value |
|------|--------|
| Product metric | Wall time for cold full re-analysis |
| Profile / flags | `--profile all --no-fail --no-cache --no-snippet --no-color true` |
| Primary corpus | gopdfsuit (`/home/chinmay/ChinmayPersonalProjects/gopdfsuit`) |
| Secondary canary | `real-repos/gorl` (`/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl`) |
| **Reopen trigger** | Cold gopdfsuit wall **consistently &gt;1.0s** on a quiet host (release, same flags), **or** a larger corpus becomes the official product SLA |
| Steady-state | Prefer repeat runs after one process warm-up; first-process outliers (disk/OS) do not alone reopen work |

This matches `perf-eval-decision.md` §3.1 / §5. No new SLA is introduced.

---

## 2. Measurement method

```bash
cargo build --release
target/release/codehound <path> \
  --profile all --no-fail --no-cache --no-snippet --no-color true
```

Wall time: scan summary line (`scanned … in Xs`) plus `/usr/bin/time -f 'TIME_WALL=%e TIME_RSS_KB=%M'`.  
Cache line must show `0 hits` (full re-analysis).

**Host:** Linux WSL-class environment (same style as prior cold-scan notes). Numbers establish sub-second vs multi-second, not lab-stable averages.

---

## 3. Measured cold-scan results (2026-07-19)

### 3.1 gopdfsuit

| Run | Scan summary wall | `/usr/bin/time` wall | Findings | Files / lines | RSS (max) |
|-----|-------------------|----------------------|----------|---------------|-----------|
| warm-up / first | 7.01s | 7.02s | 915 | 78 / 28,120 | ~35.5 MiB |
| 1 | 601.4ms | 0.61s | 915 | 78 / 28,120 | ~34.6 MiB |
| 2 | 537.4ms | 0.54s | 915 | 78 / 28,120 | ~34.5 MiB |
| 3 | 505.9ms | 0.51s | 915 | 78 / 28,120 | ~34.1 MiB |

**Summary (gopdfsuit cold, release, 0 cache hits):**

- **Wall (steady-state):** ~**0.51–0.61s** (typical after first process)
- **Findings:** **915** (10 high / 396 medium / 312 low / 197 info)
- **Top rules:** BP-1 ×181, PERF-6 ×94, PERF-32 ×59, BP-5 ×50, PERF-230 ×44
- **Cache line:** `0 hits, 78 misses (full re-analysis)`
- **Skipped:** 383 non-scanned files

**First-run 7s outlier:** process/OS cold start only; not treated as product regression. Steady-state cold full re-analysis remains **well under 1.0s**.

**vs prior (#40 decision doc):** prior wall ~0.53–0.72s with **914** findings; current **915** findings (+1 high vs prior severity split) with ~0.51–0.61s steady wall. No multi-second regression.

### 3.2 real-repos/gorl

| Run | Scan summary wall | `/usr/bin/time` wall | Findings | Files / lines | RSS (max) |
|-----|-------------------|----------------------|----------|---------------|-----------|
| 1 | 251.4ms | 0.25s | 53 | 28 / 2,640 | ~12.0 MiB |
| 2 | 72.2ms | 0.07s | 53 | 28 / 2,640 | ~12.2 MiB |
| 3 | 73.2ms | 0.07s | 53 | 28 / 2,640 | ~12.0 MiB |

**Summary (gorl cold, release):**

- **Wall (steady-state):** ~**72–73ms**
- **Findings:** **53** (0 high / 5 medium / 23 low / 25 info; 23 example-tagged)
- **Top rules:** BP-5 ×9, BP-49 ×8, PERF-35 ×7, BP-30 ×3, BP-39 ×3

Matches prior canary ballpark (53 total). No user-facing latency concern.

---

## 4. Budget check

| Criterion | Result |
|-----------|--------|
| Steady cold gopdfsuit &gt;1.0s? | **No** — ~0.51–0.61s |
| Consistent multi-second regression? | **No** |
| Larger corpus adopted as SLA? | **No** |
| Finding oracle disruption forcing redesign? | **No** — 915 vs prior 914; multiset drift is +1, not a speed/oracle crisis |

**Verdict: UNDER BUDGET.**

---

## 5. Disposition

| Item | Decision |
|------|----------|
| Engine / detector code changes | **None** |
| Flamegraph / `perf record` | **Not planned** (still deferred per #40) |
| Shared parse/fact reuse | **Not planned** |
| small-`--only` fact skip / method-set / needle batch | **Not planned** |
| On-disk tree retention / incremental reparse | **Do not pursue** (unchanged) |

**Overall for #48:** **close as not planned for this release series unless regression.**

Reopen only when **all** of (`perf-eval-decision.md` §5):

1. Release cold gopdfsuit (`--profile all --no-cache`) wall **consistently &gt;1.0s** on a quiet host, **or** a larger corpus becomes the official SLA; and  
2. Finding multiset / fingerprint oracle is frozen for before/after; and  
3. A scoped issue names a single optimization (not a bundle of high-risk refactors).

Until then, no performance implementation under this issue. Detector rewrites for speed remain out of scope.

---

## 6. Artifacts

| Artifact | Path / value |
|----------|----------------|
| This reaffirmation | `plans/v0.0.5/perf-budget-48.md` |
| Prior decision | `plans/v0.0.5/perf-eval-decision.md` |
| Prior cold-scan plan | `plans/v0.0.4/cold-scan-performance.md` |
| Architecture notes | `documents/architecture-performance.md` |
| Binary | `target/release/codehound` |
| gopdfsuit measured wall (steady) | ~**506–601ms** cold; **915** findings |
| gorl measured wall (steady) | ~**72–73ms** cold; **53** findings |
| Budget reopen | cold gopdfsuit **&gt;1.0s** wall consistently |
| Disposition | **not planned** (under budget; no code change) |

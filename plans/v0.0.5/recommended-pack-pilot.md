# Recommended-pack pilot and stop-the-line policy

> **Plan:** [`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.3  
> **Issue:** [#119](https://github.com/chinmay-sawant/codehound/issues/119) · Parent epic [#105](https://github.com/chinmay-sawant/codehound/issues/105)  
> **Branch:** `chore/recommended-pack-trust`  
> **Date:** 2026-07-21  
> **Code changes:** none (docs + re-pilot evidence)  
> **Prior pilot:** [`pending-work.md`](./pending-work.md) §3.1 (2026-07-18, 19/20 = 95% actionable)

---

## 1. Purpose

Protect product trust in `--profile recommended` after each integrated catalog batch:

1. Re-run a pinned real-repository pilot and record counts / dispositions.
2. Treat a **material false-positive regression** as stop-the-line for the affected rule family.
3. Preserve the release cold-scan budget; do not open performance rewrites without a budget breach and stable finding oracle.

This document is the operational procedure for §4.3. It does **not** expand the recommended pack or promote fixture-only rules.

---

## 2. Pilot procedure (repeatable)

### 2.1 When to run

Run after **every integrated catalog batch** that may affect detector behavior, maturity, or pack membership (Phases 1–3 integration PRs under the parallel catalog program, or any PR that edits recommended-pack rule logic).

Skip is acceptable only when the change is docs-only and does not touch detectors, profiles, maturity, or SourceIndex ownership of recommended IDs.

### 2.2 Binary and flags

```sh
cargo build --release --locked

target/release/codehound TARGET \
  --profile recommended \
  --format json \
  --json-envelope \
  --no-fail \
  --no-cache
```

Requirements:

- Release binary from the integration tree (not a stale debug build).
- `--no-cache` so cold full re-analysis is measured.
- JSON envelope for machine-countable `findingCount` / `findings[].rule_id`.
- Never treat **recommended-pack silence** as proof that an `--profile all` / `--only` family is correct (see §4.1 rubric note).

### 2.3 Pinned corpus

§4.1 (expanded decision-quality corpus with formal pin docs) is **not complete**. Until it is, the pilot uses:

| Repository | Path (local) | Pinned revision | Role |
|---|---|---|---|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | Primary continuity target (service-scale Go) |
| monsoon | `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | Active HTTP tool (RedTeamPentesting/monsoon) |
| go-retry | `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | Small clean library (sethvargo/go-retry) |

**Opportunistic expansion** via existing ignored `real-repos/*` (until §4.1 pins a larger set):

| Repository | Path | Revision (this run) | Role |
|---|---|---|---|
| gorl | `real-repos/gorl` | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | Full-catalog noise canary; recommended expect **0** |
| no-mistakes | `real-repos/no-mistakes` | `0a2c82f993b9467c5ab84992313dfd13b66830af` | Larger third-party tree for recommended-pack smoke |

Do not commit cloned trees (`real-repos/` is gitignored). Record remote + SHA in the pilot results table each time.

When §4.1 ships a formal pin list, replace the opportunistic rows with that list and keep the three core targets unless the pin list supersedes them.

### 2.4 Finding-review rubric

Reuse the Phase 3 / §4.1 dispositions:

| Label | Meaning |
|---|---|
| **Actionable** | A competent Go engineer would change production code or accept a documented suppress with reason |
| **Narrower-policy signal** | Real shape but product may later tighten/exclude (e.g. defer+return, one-shot setup) |
| **False positive** | Should not fire under the rule’s stated contract |
| **Duplicate** | Same underlying issue already counted at another location |
| **No hit** | Repository clean for recommended pack |

**Sample rule (core three repos):** re-validate the prior 20-row senior sample (17 gopdfsuit PERF-1 in lexical order + 3 monsoon findings) when counts match the last pilot; if counts change, re-sample all new/changed locations plus enough stable rows to keep N≥20.

**Actionability bar:** ≥70% actionable on the reviewed sample. Prefer family-level quarantine/narrowing over weakening global quality gates when the bar fails.

### 2.5 What to record

For each target: SHA, files scanned, finding count, multiset of `rule_id`, wall time (optional), and disposition notes for every **new or changed** finding relative to the previous pilot.

---

## 3. Stop-the-line policy (material FP regression)

### 3.1 Definition

A **material false-positive regression** on a recommended-pack family is any of:

1. **New FP on a previously clean recommended-pack location** introduced by a detector/maturity/profile change in the batch under review; or
2. **Reviewed sample actionability drops below 70%** for the core corpus sample; or
3. **Family-level noise spike:** a single recommended rule gains **≥3 new false positives** on the pinned core corpus (gopdfsuit + monsoon + go-retry) versus the last recorded pilot multiset, after senior disposition.

“New” means the finding was absent at the prior pilot’s CodeHound SHA on the same target revision.

### 3.2 What is not stop-the-line

- Full-catalog (`--profile all`) noise on non-recommended rules.
- Fixture-only rules remaining available under `--profile all` (by design).
- Pre-existing known FPs already documented in the last pilot (e.g. monsoon PERF-1 setup compile) **unless** their count multiplies or the rule spreads to more clean modules.
- First-process wall-time outliers on cold scan (see §4).

### 3.3 Required response

When stop-the-line trips:

1. **Block** merge of the integration / pack-affecting PR (or revert the family on the integration branch).
2. **Open or convert** a focused issue scoped to the **affected rule family** (not a global “relax gates” issue).
3. **Prefer** narrow / quarantine / re-tier / remove for that family — matching Phase 3.1 practice (PERF-7 function-literal exclusion).
4. **Do not** weaken `make lint` / `make test` / fixture oracle / release canary gates to absorb the FP.
5. **Do not** expand recommended pack membership to compensate.

Global quality gates stay strict. The family is the unit of rollback.

### 3.4 Owner surfaces

| Surface | Owner when stop-the-line fires |
|---|---|
| Detector subtree for the family | Family worktree / follow-up issue |
| Profile allow-list / maturity | Integration owner only |
| This pilot doc | Updated with the regression multiset and disposition |

---

## 4. Release cold-scan budget status

Authoritative budget: [`perf-budget-48.md`](./perf-budget-48.md) and [`perf-eval-decision.md`](./perf-eval-decision.md).

| Item | Value |
|---|---|
| Metric | Cold full re-analysis wall time |
| Command | `target/release/codehound <gopdfsuit> --profile all --no-fail --no-cache --no-snippet --no-color true` |
| Reopen trigger | Steady cold gopdfsuit wall **consistently >1.0s** on a quiet host, **or** a larger corpus becomes the product SLA |
| Oracle | Finding multiset must remain stable enough to interpret speed (not a redesign crisis) |

### 4.1 Status on 2026-07-21 (this pilot)

| Run | Scan summary wall | `/usr/bin/time` wall | Findings |
|---:|---:|---:|---:|
| steady 1 | 748.4ms | 0.76s | **915** |
| steady 2 | 515.4ms | 0.52s | **915** |
| steady 3 | 698.5ms | 0.85s | **915** |
| steady 4 | 623.1ms | 0.65s | **915** |

- **Steady wall:** ~0.52–0.85s (under 1.0s).
- **Findings:** 915 (10 high / 396 medium / 312 low / 197 info); top rules BP-1 ×181, PERF-6 ×94, PERF-32 ×59, BP-5 ×50, PERF-230 ×44.
- **Cache:** 0 hits / 78 misses (full re-analysis).
- Matches prior reaffirmation in `perf-budget-48.md` (915 findings, sub-second steady wall).

**Verdict: UNDER BUDGET — hold performance rewrites.**  
Do not start release-grade perf work unless this budget is breached with a stable oracle.

---

## 5. Pilot results — 2026-07-21 (post Phase 2 integration)

### 5.1 Environment

| Item | Value |
|---|---|
| CodeHound tree | `7d912d5be8528f80df0122259d24130c6f394df9` (`origin/master` after epic #105 Phase 2 integration) |
| Binary | `target/release/codehound` 0.1.0 (release, built at that SHA) |
| Host | Linux WSL-class (same class as prior cold-scan notes) |
| Profile | `recommended` |

### 5.2 Counts

| Repository | Revision | Files scanned | Findings | By rule |
|---|---|---:|---:|---|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **38** | PERF-1 ×38 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **3** | PERF-1 ×1, PERF-7 ×1, PERF-190 ×1 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** | — |
| gorl (extra) | `ec54aaf1…` | 28 | **0** | — |
| no-mistakes (extra) | `0a2c82f9…` | 222 | **2** | PERF-189 ×1, PERF-7 ×1 |

**Core three total:** 41 findings — **identical multiset** to the post-PERF-7 pilot in `pending-work.md` §3.1 (38 + 3 + 0).

Reproduce:

```sh
target/release/codehound /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
  --profile recommended --format json --json-envelope --no-fail --no-cache
target/release/codehound real-repos/monsoon \
  --profile recommended --format json --json-envelope --no-fail --no-cache
target/release/codehound real-repos/go-retry \
  --profile recommended --format json --json-envelope --no-fail --no-cache
```

### 5.3 Disposition (core sample)

The prior senior 20-row sample remains valid: counts and locations for monsoon are unchanged; gopdfsuit remains PERF-1-only at the same xfdf/helpers/merge/redact sites.

| # | Location | Rule | Disposition |
|---:|---|---|---|
| 1–17 | gopdfsuit `internal/pdf/form/xfdf.go` (first 17 PERF-1 in prior lexical sample) | PERF-1 | **Actionable** — literal regexp compiled per loop iteration |
| 18 | monsoon `cmd/fuzz/main.go:91` | PERF-1 | **False positive** — one-shot setup compile of input patterns |
| 19 | monsoon `reporter/reporter.go:202` | PERF-7 | **Actionable** — loop-level defer accumulates until function return |
| 20 | monsoon `response/runner.go:293` | PERF-190 | **Actionable** — long-lived `http.Client` without `Timeout` |

**Sample actionability:** 19/20 = **95.0%** (unchanged; ≥70% bar).  
**All core findings:** 40/41 = **97.6%** actionable if monsoon PERF-1 is the only FP (unchanged).

**Stop-the-line:** **not triggered** — no material FP regression vs 2026-07-18 pilot after Phase 1–2 catalog integration.

### 5.4 Extended corpus notes (not stop-the-line)

| Location | Rule | Disposition | Notes |
|---|---|---|---|
| no-mistakes `internal/telemetry/telemetry.go:305` | PERF-189 | **False positive** (lexical) | `defer resp.Body.Close()` then `io.Copy(io.Discard, …)` — runtime drain occurs before close; detector messages as Close-before-drain |
| no-mistakes `internal/update/archive.go:58` | PERF-7 | **Narrower-policy / FP** | `defer rc.Close()` then immediate `return` inside loop — no multi-defer accumulation |

These are **not** regressions from Phase 2 CWE catalog work (recommended pack did not gain those CWE IDs; counts on core three are stable). Track as optional PERF-189/PERF-7 proof-boundary follow-ups; do **not** weaken gates or expand packs to hide them.

gorl recommended **0** remains the full-catalog noise canary control.

---

## 6. Pilot results — 2026-07-23 (post epic #151 R1–R8 / P1)

### 6.1 Environment

| Item | Value |
|---|---|
| CodeHound tree | `f3eaaf8a28a79fc53d4ca78acbd448294e0aeab8` (`origin/master` after #176 + #177) |
| Binary | `target/release/codehound` 0.1.0 (release, built at that SHA) |
| Host | Linux WSL-class |
| Profile | `recommended` |

### 6.2 Counts

| Repository | Revision | Files scanned | Findings | By rule |
|---|---|---:|---:|---|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **38** | PERF-1 ×38 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **3** | PERF-1 ×1, PERF-7 ×1, PERF-190 ×1 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** | — |
| gorl (extra) | `ec54aaf1…` | 28 | **0** | — |
| no-mistakes (extra) | `0a2c82f9…` | 222 | **2** | PERF-189 ×1, PERF-7 ×1 |

**Core three total:** 41 — **identical multiset** to §5 (2026-07-21). No new/changed recommended findings after R1–R8 FO quarantine.

### 6.3 Disposition / stop-the-line

Prior senior 20-row sample remains valid (counts/locations unchanged).  
**Sample actionability:** 19/20 = **95.0%** (≥70% bar).  
**Stop-the-line:** **not triggered** — no material FP regression on recommended pack.

Extended no-mistakes PERF-189 / PERF-7 rows unchanged (pre-existing; not catalog-batch regressions).

### 6.4 Cold-scan budget (gopdfsuit `--profile all --no-cache`)

| Run | Scan summary wall | `/usr/bin/time` wall | Findings |
|---:|---:|---:|---:|
| 1 | 859.3ms | 0.87s | **915** |
| 2 | 482.1ms | 0.50s | **915** |
| 3 | 545.1ms | 0.56s | **915** |

- **Steady wall:** ~0.50–0.87s (under 1.0s reopen trigger).
- **Findings:** 915 (stable vs §4.1).
- **Verdict: UNDER BUDGET — hold performance rewrites.**

---

## 7. Checklist for future batches

- [ ] Release binary rebuilt from integration SHA
- [ ] Core three recommended scans recorded (counts + rule multiset)
- [ ] Compare to previous pilot table; list new/changed findings
- [ ] Re-sample / re-disposition if multiset changed
- [ ] Stop-the-line decision: clear / fire (with family issue)
- [ ] Cold-scan gopdfsuit `--profile all --no-cache` steady wall noted (hold vs reopen)
- [ ] Link results from the integration PR and update this file’s dated section

---

## 8. References

- Pack definition: [`documents/go-recommended-pack.md`](../../documents/go-recommended-pack.md)
- Prior Phase 3 pilot: [`pending-work.md`](./pending-work.md) §3.1
- Cold-scan budget: [`perf-budget-48.md`](./perf-budget-48.md), [`perf-eval-decision.md`](./perf-eval-decision.md)
- Catalog program ledger: [`parallel-catalog-program.md`](./parallel-catalog-program.md) §4.3
- Fixture-only quarantine: [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md)

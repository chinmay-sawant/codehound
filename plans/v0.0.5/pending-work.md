# v0.0.5 — Pending Work Reconciliation Checklist

> **Parent:** `ROADMAP.md` — live 0.1.x product direction; this file is a one-time reconciliation snapshot for historical unchecked boxes, not a replacement roadmap.
> **Status:** Phases 1–2 and noise-reduce-1 are complete (PR [#38](https://github.com/chinmay-sawant/codehound/pull/38)). Next active implementation work is **CWE catalog trust tranche 2** ([#39](https://github.com/chinmay-sawant/codehound/issues/39)). Phase 4 remains decision-gated and must not start under #39.
> **Estimated effort:** CWE tranche 2 is issue-scoped under #39; Phase 4 stays out of scope until separately approved.

---

## Overview

This checklist consolidates every Markdown `- [ ]` row currently present in the repository into a single, evidence-based management view. The scan found **741 raw unchecked boxes in 32 files**. Most are intentionally not current implementation work: archived plans, duplicated deferred snapshots, research candidate lists, PR templates, or struck/skipped rows.

The purpose of this document is to prevent historical plan text from being mistaken for an active release commitment. Keep `ROADMAP.md` and GitHub issues as the product source of truth; use this file to close, defer, or promote the surviving outcomes with evidence.

---

## Executive Summary

- Cold-scan acceptance is **complete**: a release-binary, no-cache scan of gopdfsuit completed in **235.8 ms** with the unchanged 943-finding oracle. The earlier 462.7 ms observation is not a release blocker.
- Existing-pack BP trust cleanup and the recommended-pack real-repository pilot are **complete** (Phases 2–3.1).
- **noise-reduce-1 is closed:** pinned gorl full-catalog canary is **53 findings** (23 example-tagged, 30 non-example); recommended remains **0**. Evidence: `plans/v0.0.5/noise-reduce-1.md` (all checklist items done), PR [#38](https://github.com/chinmay-sawant/codehound/pull/38) merged, PR record `plans/v0.0.5/pr-pending-items.md`.
- **Next active work** is CWE catalog trust (Phase 3.2 remaining rows), gated by GitHub issue [#39](https://github.com/chinmay-sawant/codehound/issues/39): long-tail NEEDLES audit, call-facts pilot, maturity expansion from evidence. Do not treat historical BP research lists as open implementation under #39.
- Advanced taint modelling, 29 absent BP candidates, optional performance micro-optimizations, typed Go facts, and Python investment remain **decision-gated**. They must not be started under #39 or merely because an old document contains an unchecked box.

**Success criteria:** every active outcome has a reproducible validation result and an explicit disposition; no archival checklist remains implicitly presented as live work; `ROADMAP.md` and `CHANGELOG.md` are updated when a shipped decision affects product scope.

---

## Phase 0: Establish One Auditable Backlog

### 0.1 Preserve the audit boundary

- [x] Record the Phase 1–3 decisions in the owning source documents and update `ROADMAP.md`: cold-scan, BP canary, and recommended-pack pilot evidence are now linked from their owning documents.
- [x] For each archived source below, mark its surviving outcome as completed, deferred, or superseded only after source/test evidence is attached; do not bulk-check historical rows. Dispositions for the 0.2 index are recorded in **Archived source dispositions (evidence-backed)** — each row is labeled completed, deferred, or superseded from the index disposition text and owning-phase outcomes; archived file checkboxes were **not** bulk-ticked.
- [x] Remove the stale claim that Go taint integration tests are ignored and correct the stale IP-007/IP-008 deferred manifest comment; the active integration suite runs the registered cases, while channel/goroutine flows remain an explicit unsupported boundary.
- [x] Keep `plans/v0.0.5/pending-work.md` as this reconciliation snapshot; create an issue for any item selected for implementation. **Issue opened:** [#39](https://github.com/chinmay-sawant/codehound/issues/39) — *CWE catalog trust tranche 2: NEEDLES audit + call-facts pilot* (open).

### 0.2 Complete unchecked-box source index

| Raw boxes | Source | Disposition in this checklist |
|---:|---|---|
| 77 | `plans/v0.0.3/deferred/agent2-v2-core.md` | Archived duplicate snapshot; source only |
| 69 | `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` | BP research candidates; aggregate deferred in Phase 4 |
| 56 | `plans/v0.0.3/deferred/agent1-p2-implementation.md` | Archived duplicate snapshot; source only |
| 49 | `plans/v0.0.3/new-bad-practices/CHECKLIST.md` | Current BP quality/canary outcomes in Phases 2 and 4 |
| 49 | `plans/v0.0.3/deferred/agent4-pending-work.md` | Archived duplicate snapshot; source only |
| 37 | `plans/v0.0.3/pending-work_v3.0.0.md` | Stale and internally conflicting; re-verify before promotion |
| 37 | `plans/v0.0.3/new-bad-practices/03-part-c-http-frameworks.md` | BP research candidates; aggregate deferred in Phase 4 |
| 30 | `plans/v0.0.3/new-bad-practices/04-part-d-data-persistence.md` | BP research candidates; aggregate deferred in Phase 4 |
| 28 | `plans/feedback/10072026/action-items.md` | Product-trust outcomes in Phase 3; remaining rows are historical/deferred |
| 27 | `plans/v0.0.2/ponytail/ultra-audit-report.md` | Archived audit / skipped rows; not current work |
| 24 | `plans/v0.0.3/new-bad-practices/07-implementation-order.md` | BP research sequencing; aggregate deferred in Phase 4 |
| 24 | `plans/v0.0.3/new-bad-practices/02-part-b-concurrency-resources.md` | BP research candidates; aggregate deferred in Phase 4 |
| 23 | `plans/v0.0.3/new-bad-practices/05-part-e-observability-config.md` | BP research candidates; aggregate deferred in Phase 4 |
| 23 | `plans/feedback/10072026/improvements.md` | Historical feedback; promote only through `ROADMAP.md` |
| 22 | `plans/v0.0.3/deferred/agent5-v0.0.1.md` | Archived duplicate snapshot; source only |
| 21 | `plans/v0.0.3/deferred/agent3-antipattern-review.md` | Archived duplicate snapshot; source only |
| 21 | `plans/v0.0.3/PR/pr-bp-implementations-catalog-and-engine-quality_16072026.md` | PR artifact/template, not a backlog |
| 19 | `plans/v0.0.3/new-bad-practices/00-gap-and-scope.md` | BP research scope; aggregate deferred in Phase 4 |
| 19 | `plans/feedback/PR.md` | PR artifact/template, not a backlog |
| 17 | `plans/v0.0.3/new-bad-practices/06-part-f-testing-api-hygiene.md` | BP research candidates; aggregate deferred in Phase 4 |
| 14 | `plans/v0.0.4/PR.md` | PR artifact/template, not a backlog |
| 11 | `plans/PR/PR_TEMPLATE.md` | Template placeholders, not a backlog |
| 10 | `plans/v0.0.4/cold-scan-performance.md` | One required acceptance gate in Phase 1; optional work in Phase 4 |
| 6 | `plans/v0.0.3/performance_analysis.md` | Superseded by v0.0.4 measurements |
| 5 | `plans/v0.0.3/new-bad-practices/README.md` | Research links/policy; not independent tasks |
| 5 | `plans/v0.0.3/executive-summary.md` | Historical summary; not independent tasks |
| 4 | `plans/v0.0.2/consolidated_pendingtask_02072026.md` | Historical / skipped rows; not current work |
| 3 | `plans/v0.0.2/plan-improvements-06072026.md` | Historical plan; not current work |
| 3 | `plans/v0.0.2/enhanced-patterns/CHECKLIST.md` | Historical feature plan; promote only with new evidence |
| 3 | `documents/rule-rfc-template.md` | Documentation template, not a backlog |
| 2 | `plans/v0.0.2/enhanced-patterns/04-implementation-order.md` | Historical feature plan; not current work |
| 2 | `AGENTS.md` | Instruction-template examples, not a backlog |
| 1 | `plans/v0.0.2/enhanced-patterns/README.md` | Historical feature plan; not current work |

### Archived source dispositions (evidence-backed)

Dispositions below are justified from the 0.2 index labels and completed Phase 1–3 outcomes. They do **not** bulk-check boxes inside the archived files.

| Source | Label | Disposition note |
|---|---|---|
| `plans/v0.0.3/PR/pr-bp-implementations-catalog-and-engine-quality_16072026.md` | **superseded / not backlog** | PR artifact/template, not an implementation backlog |
| `plans/feedback/PR.md` | **superseded / not backlog** | PR artifact/template, not a backlog |
| `plans/v0.0.4/PR.md` | **superseded / not backlog** | PR artifact/template, not a backlog |
| `plans/PR/PR_TEMPLATE.md` | **superseded / not backlog** | Template placeholders only |
| `documents/rule-rfc-template.md` | **superseded / not backlog** | Documentation template, not a backlog |
| `AGENTS.md` | **superseded / not backlog** | Instruction-template examples, not a backlog |
| `plans/v0.0.3/performance_analysis.md` | **superseded / not backlog** | Superseded by v0.0.4 cold-scan measurements (Phase 1 closed) |
| `plans/v0.0.3/executive-summary.md` | **superseded / not backlog** | Historical summary; not independent tasks |
| `plans/v0.0.3/new-bad-practices/README.md` | **superseded / not backlog** | Research links/policy only; not independent tasks |
| `plans/v0.0.2/ponytail/ultra-audit-report.md` | **superseded / not backlog** | Archived audit / skipped rows; not current work |
| `plans/v0.0.2/consolidated_pendingtask_02072026.md` | **superseded / not backlog** | Historical / skipped rows; not current work |
| `plans/v0.0.2/plan-improvements-06072026.md` | **superseded / not backlog** | Historical plan; not current work |
| `plans/v0.0.2/enhanced-patterns/CHECKLIST.md` | **superseded / not backlog** | Historical feature plan; promote only with new evidence (none attached) |
| `plans/v0.0.2/enhanced-patterns/04-implementation-order.md` | **superseded / not backlog** | Historical feature plan; not current work |
| `plans/v0.0.2/enhanced-patterns/README.md` | **superseded / not backlog** | Historical feature plan; not current work |
| `plans/v0.0.4/cold-scan-performance.md` | **completed** (gate) / **deferred** (optional) | Required acceptance gate closed in Phase 1; optional micro-opts remain decision-gated in Phase 4 |
| `plans/feedback/10072026/action-items.md` | **completed** (product-trust slice) / **deferred** (remainder) | Phase 3 product-trust outcomes closed; remaining historical rows not promoted |
| `plans/feedback/10072026/improvements.md` | **deferred** | Historical feedback; promote only through `ROADMAP.md` — not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/deferred/agent1-p2-implementation.md` | **deferred** | Archived agent dump; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/deferred/agent2-v2-core.md` | **deferred** | Archived agent dump; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/deferred/agent3-antipattern-review.md` | **deferred** | Archived agent dump; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/deferred/agent4-pending-work.md` | **deferred** | Archived agent dump; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/deferred/agent5-v0.0.1.md` | **deferred** | Archived agent dump; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/pending-work_v3.0.0.md` | **deferred** | Stale and internally conflicting; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/CHECKLIST.md` | **completed** (quality/canary) / **deferred** (expansion) | Existing-pack quality/canary outcomes closed in Phases 2–3; BP expansion candidates deferred in Phase 4 |
| `plans/v0.0.3/new-bad-practices/00-gap-and-scope.md` | **deferred** | BP research scope; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/01-part-a-core-language.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/02-part-b-concurrency-resources.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/03-part-c-http-frameworks.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/04-part-d-data-persistence.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/05-part-e-observability-config.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/06-part-f-testing-api-hygiene.md` | **deferred** | BP research candidates; not promoted; still decision-gated in Phase 4 |
| `plans/v0.0.3/new-bad-practices/07-implementation-order.md` | **deferred** | BP research sequencing; not promoted; still decision-gated in Phase 4 |

---

## Phase 1: Close the Cold-Scan Acceptance Gate — Completed

### 1.1 Release cold-scan evidence


- [x] Run the release binary on gopdfsuit with `--no-fail --no-terminal --profile all --no-cache`: 78 files / 28,120 lines completed in **235.8 ms** with 0 cache hits and 78 misses.
- [x] Preserve the cold-scan finding oracle: the release scan reported **943 findings**, matching the established oracle and remaining within the prior 229.4 ms best / 272 ms p50 operating band.
- [x] Classify the 462.7 ms observation as non-blocking workflow/host variance rather than a reproducible release-scanner regression.
- [x] Close the cold-scan acceptance gate. Reopen only if the exact release, no-cache command regresses materially while preserving the same workload and finding oracle.

### 1.2 Guard semantic correctness

- [x] Confirm semantic equivalence through the unchanged 943-finding release-scan oracle.
- [x] Confirm no code change was needed to close the gate; the repository lint baseline remained green.

---

## Phase 2: Make the Bad-Practice Pack Trustworthy

### 2.1 Audit existing-pack precision

- [x] BP-1: retained conservative discard shapes, documented the no-type-facts limitation, and added vulnerable/safe `os.Stat` variants instead of widening every ignored call.
- [x] BP-6: AST-scoped Add matching handles nested blocks; a nested-goroutine exact-count regression proves the inner Add reports once.
- [x] BP-8: require the same by-value mutex parameter in functions and methods; pointer unlocks in the same file no longer trigger.
- [x] BP-9: inspect parsed select statements and direct cases, so nested braces, nested selects, and `select`/cancellation lookalikes in comments and strings cannot affect findings.
- [x] BP-12 and BP-14: labelled as review-only heuristics because local source cannot prove ownership, cancellation, or helper lifecycle control.
- [x] BP-46..BP-55: audited project-level lifecycle findings; BP-47/50/54/55 now explicitly report missing project-visible evidence and remain review-only for external ownership boundaries.
- [x] BP-56..BP-65: documented BP-57..BP-65 as one-per-project module audits rather than source findings; BP-63 remains reserved and is not a live vulnerability feed.

### 2.2 Document and validate the boundaries

- [x] Add an explicit review-required contract for detectors without type, ownership, alias, or control-flow proof; BP-1, BP-6, BP-12, and BP-14 now state their precise limits in metadata and `documents/bad-practices.md`.
- [x] Reconcile stale v0.0.2 BP pending-work wording with the shipped catalog without rewriting history: the v0.0.2 file remains an MVP snapshot (13 rules, BP-12/14 reserved), while current evidence is the 136-rule generated registry, dispatch, fixtures, and integration suite.
- [x] Add or tighten a vulnerable fixture, safe near-miss fixture, and structural/identifier variant for each changed detector: BP-1, BP-6, BP-8, and BP-9 have focused coverage.
- [x] Run `cargo test --test go_bad_practice_integration`, `make test`, and `make lint` for the completed existing-pack trust-cleanup batch: 394 Nextest tests plus one doctest and strict all-feature linting passed.
- [x] Record changed false-positive/false-negative behavior before considering another BP catalog expansion; preserve the new advisory/review-only boundaries.

### 2.3 Test in representative modules

- [x] Scan the clean `tests/canary/clean_lib` module with `--profile recommended` and changed-rule BP selection (`BP-1,BP-6,BP-8,BP-9`): 0 findings in both runs; `go vet ./...` and staticcheck were clean.
- [x] Scan the representative Gin HTTP service at `/home/chinmay/ChinmayPersonalProjects/gopdfsuit`: recommended reported 45 findings (PERF-1 ×38, PERF-7 ×7); the changed BP selection reported BP-1 ×181, BP-6 ×2, BP-8 ×0, and BP-9 ×0.
- [x] Compare both targets with `go vet ./...` and staticcheck: both linters were clean, so no canary finding is a duplicate of those two tools; classifications are recorded below.

#### 2.3.1 Canary evidence and classification

The target revisions were CodeHound detector source `c23bf18` (the release binary used for the scan) and gopdfsuit `26d71268937136036c3be1770c0f7bdd89f87dc6` (clean worktree). Commands used the release binary with `--no-cache`; BP scans explicitly used `--profile all --only BP-1,BP-6,BP-8,BP-9` because BP is correctly disabled in the recommended pack. Both external-linter commands were run with temporary Go/XDG caches:

```sh
target/release/codehound tests/canary/clean_lib --no-fail --no-terminal --profile recommended --no-cache
target/release/codehound tests/canary/clean_lib --no-fail --no-terminal --profile all --only BP-1,BP-6,BP-8,BP-9 --no-cache --format json
target/release/codehound /home/chinmay/ChinmayPersonalProjects/gopdfsuit --no-fail --no-terminal --profile recommended --no-cache
target/release/codehound /home/chinmay/ChinmayPersonalProjects/gopdfsuit --no-fail --no-terminal --profile all --only BP-1,BP-6,BP-8,BP-9 --no-cache --format json
(cd tests/canary/clean_lib && GOCACHE=/tmp/codehound-canary-go-cache XDG_CACHE_HOME=/tmp/codehound-canary-xdg go vet ./...)
(cd tests/canary/clean_lib && GOCACHE=/tmp/codehound-canary-go-cache XDG_CACHE_HOME=/tmp/codehound-canary-xdg staticcheck ./...)
(cd /home/chinmay/ChinmayPersonalProjects/gopdfsuit && GOCACHE=/tmp/codehound-canary-go-cache XDG_CACHE_HOME=/tmp/codehound-canary-xdg go vet ./...)
(cd /home/chinmay/ChinmayPersonalProjects/gopdfsuit && GOCACHE=/tmp/codehound-canary-go-cache XDG_CACHE_HOME=/tmp/codehound-canary-xdg staticcheck ./...)
```

| Target / signal | Count | Actionable | Narrower policy signal | False positive | Duplicate |
|---|---:|---:|---:|---:|---:|
| `tests/canary/clean_lib`, recommended + changed BP subset | 0 | 0 | 0 | 0 | 0 |
| gopdfsuit, `PERF-1` regex compilation in loop | 38 | 38 | 0 | 0 | 0 |
| gopdfsuit, `PERF-7` defer inside goroutine closure launched by a loop | 7 | 0 | 0 | 7 | 0 |
| gopdfsuit, `BP-1` discarded parse/I/O error paths | 93 | 93 | 0 | 0 | 0 |
| gopdfsuit, `BP-1` explicit cleanup/optional-fallback/known-safe operation discards | 59 | 0 | 59 | 0 | 0 |
| gopdfsuit, `BP-1` non-error tuple and other untyped discard shapes | 29 | 0 | 0 | 29 | 0 |
| gopdfsuit, `BP-6` atomic-counter `.Add` calls inside goroutines | 2 | 0 | 0 | 2 | 0 |

The 181 BP-1 rows are fully partitioned (93 + 59 + 29). The 45 recommended rows are fully partitioned (38 + 7). Location-level source review used the JSON `file` and `line` fields from the fourth command above at the pinned gopdfsuit revision: each BP-1 row is in exactly one of the three BP-1 classes, every `PERF-1` and `PERF-7` row is in its corresponding row above, and the two BP-6 locations are `internal/benchmarktemplates/runner.go:98` and `sampledata/benchmarks/gopdflib/databench_gopdflib.go:154`. This is the disposition ledger for this pilot; re-run the recorded JSON command if the target revision changes. BP-6 is re-tiered as review-required until a conservative receiver-type proof is available; do not broaden the BP catalog or alter gopdfsuit in this CodeHound validation slice.

---

## Phase 3: Establish Recommended-Pack Product Trust

### 3.1 Run the real-repository pilot

- [x] Triage a senior-reviewed sample of 20 recommended-pack findings from real Go repositories and measure whether at least 70% are actionable: 19/20 (95.0%) were actionable.
- [x] Publish the sample criteria, repository revisions, rule IDs, finding disposition, and actionability calculation below; the pilot uses real source, not fixtures.
- [x] Use failures from the pilot to narrow, quarantine, re-tier, or remove rules rather than adding compensating rules: PERF-7 now excludes a function literal declared by its nearest enclosing loop.

#### 3.1.1 Real-repository sample (2026-07-18)

The pilot cloned public repositories into ignored `real-repos/` without modifying their source. Selection was intentionally modest rather than a mega-project: `sethvargo/go-retry` (712 GitHub stars, small Go library) and `RedTeamPentesting/monsoon` (497 GitHub stars, active HTTP enumeration tool). The existing gopdfsuit HTTP service remains in the sample to preserve continuity with Phase 2.

| Repository | Revision | Recommended findings before PERF-7 narrowing | Findings after narrowing |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 45 (PERF-1 ×38, PERF-7 ×7) | 38 (PERF-1 ×38) |
| `real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 3 (PERF-1, PERF-7, PERF-190) | 3 (PERF-1, PERF-7, PERF-190) |
| `real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 0 | 0 |

The baseline used CodeHound `4d7e4bb`; the rerun used the current debug build after the PERF-7 fix because the shared release target directory was locked by another local Cargo process. Reproduce the post-fix counts with:

```sh
target/debug/codehound --no-fail --profile recommended --no-cache --format json /home/chinmay/ChinmayPersonalProjects/gopdfsuit
target/debug/codehound --no-fail --profile recommended --no-cache --format json real-repos/monsoon
target/debug/codehound --no-fail --profile recommended --no-cache --format json real-repos/go-retry
```

Senior-review attestation: the CodeHound senior-maintainer agent reviewed each listed source location and disposition in this session on 2026-07-18. Sample rule: include the three monsoon findings plus the first 17 gopdfsuit PERF-1 locations in lexical `file:line` order. This avoids choosing only the successful rule while keeping the detailed source review to 20 rows.

| # | Repository / location | Rule | Disposition | Source-review reason |
|---:|---|---|---|---|
| 1 | gopdfsuit `internal/pdf/form/xfdf.go:1239` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 2 | gopdfsuit `internal/pdf/form/xfdf.go:1252` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 3 | gopdfsuit `internal/pdf/form/xfdf.go:1254` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 4 | gopdfsuit `internal/pdf/form/xfdf.go:1260` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 5 | gopdfsuit `internal/pdf/form/xfdf.go:1286` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 6 | gopdfsuit `internal/pdf/form/xfdf.go:348` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 7 | gopdfsuit `internal/pdf/form/xfdf.go:360` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 8 | gopdfsuit `internal/pdf/form/xfdf.go:362` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 9 | gopdfsuit `internal/pdf/form/xfdf.go:364` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 10 | gopdfsuit `internal/pdf/form/xfdf.go:369` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 11 | gopdfsuit `internal/pdf/form/xfdf.go:402` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 12 | gopdfsuit `internal/pdf/form/xfdf.go:441` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 13 | gopdfsuit `internal/pdf/form/xfdf.go:497` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 14 | gopdfsuit `internal/pdf/form/xfdf.go:509` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 15 | gopdfsuit `internal/pdf/form/xfdf.go:804` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 16 | gopdfsuit `internal/pdf/form/xfdf.go:813` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 17 | gopdfsuit `internal/pdf/form/xfdf.go:828` | PERF-1 | Actionable | Literal regular expression is compiled for every loop iteration. |
| 18 | monsoon `cmd/fuzz/main.go:91` | PERF-1 | False positive | Each pattern is input-dependent and must be compiled once during setup; it is not a repeated hot-path compile. |
| 19 | monsoon `reporter/reporter.go:202` | PERF-7 | Actionable | Direct loop-level defer accumulates until the reporter function returns. |
| 20 | monsoon `response/runner.go:293` | PERF-190 | Actionable | Long-lived `http.Client` has no deadline and can hang requests. |

`19 / 20 = 95.0%` actionable, exceeding the 70% pilot bar. Across every post-fix recommended finding in the three repositories, `40 / 41 = 97.6%` are actionable (38 gopdfsuit PERF-1 + monsoon PERF-7/PERF-190); monsoon PERF-1 is the only reviewed false positive.

#### 3.1.2 PERF-7 narrowing result

The seven gopdfsuit false positives were `defer wg.Done()` or semaphore cleanup inside a function literal launched by an outer loop. Such defers execute when each closure returns, so they do not accumulate at the outer function exit. PERF-7 now records function-literal spans and ignores only this nearest-loop boundary. A loop nested inside that closure remains reportable. The canonical PERF-007 vulnerable fixture still fires; the safe fixture now covers a per-iteration function literal.

### 3.2 Continue catalog honesty

Open CWE rows below are tracked by GitHub issue [#39](https://github.com/chinmay-sawant/codehound/issues/39); they remain **open** until tranche 2 produces evidence. Do not mark them done from this reconciliation alone.

- [x] Audit the CWE long-tail needles and expand the maturity table from evidence. Tranche 1: CWE-334/335/338/342/343/798 fixture-only. Tranche 2: CWE-1204/1240 fixture-only; CWE-325 remains Heuristic. See `plans/v0.0.5/cwe-catalog-trust-audit.md`. Further domains remain under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Define and enforce the rewrite bar before promoting a rule to `structural` maturity; the bar, evidence requirements, and same-change maturity/profile update rule are recorded in `plans/v0.0.5/cwe-catalog-trust-audit.md`.
- [x] Prefer call facts and callee classification over `SourceIndex.has` as the primary detector signal where the currently selected rule proves that feasible. **Pilot:** CWE-918 (`http.Get` SSRF) now emits from `call_facts` + user-controlled URL binding; SourceIndex is prefilter/negative gate only (`cwe-catalog-trust-audit.md` §2.1). Broader rewrites continue under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Use NEEDLES as negative gates where possible and complete the remaining NEEDLES-comment pass incrementally. **Pilot:** Tranche 2 cipher NEEDLES labeled `negative-gate:` / `fixture-literal:` in `source_index.rs` (§2.2). Remaining NEEDLES pass continues under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Track canary hit rates and create a dated deletion/review decision for rules with zero useful hits. Tranche 1 (0/126) and Tranche 2 cipher family (0/126) recorded with keep/quarantine decisions; not deleted solely for zero hits. Further families under [#39](https://github.com/chinmay-sawant/codehound/issues/39).
- [x] Execute the pinned gorl full-catalog noise-reduction plan one issue-sized detector batch at a time — **completed / superseded by closed plan.** Evidence: `plans/v0.0.5/noise-reduce-1.md` (all checkboxes done; plan **Closed**); final canary **53** findings (**23** example-tagged, **30** non-example), recommended **0**; PR [#38](https://github.com/chinmay-sawant/codehound/pull/38) merged 2026-07-18; PR record `plans/v0.0.5/pr-pending-items.md`. Intermediate 85→75 initial tranche is historical; further detector batches require a new issue (next: #39 for CWE, not additional BP/PERF noise batches under this closed plan).

---

## Phase 4: Decision-Gated and Explicitly Deferred Work

**Status: deferred — do not implement under issue #39; require separate approval.**

Nothing in this phase is a v0.0.5 commitment. Create a scoped issue and obtain fresh evidence before changing any checkbox to active.

### 4.1 Deferred BP-66..BP-165 candidates

- [ ] Reassess the 29 absent BP candidates only after real-module canaries provide a concrete, statically provable pattern.
- [ ] Core/context candidates (BP-69, BP-71, BP-74, BP-77, BP-78): require a sound contract, alias, or interprocedural proof boundary.
- [ ] HTTP/framework candidates (BP-103, BP-106, BP-108, BP-112..BP-115, BP-118, BP-121, BP-123..BP-125): require framework/lifecycle or policy evidence beyond generic syntax.
- [ ] Data candidates (BP-127, BP-129, BP-130, BP-137, BP-139, BP-144): require driver, query, configuration, or intent evidence not currently available.
- [ ] Observability/API candidates (BP-148, BP-150, BP-152, BP-153, BP-157, BP-165): require environment, security-policy, or multi-file ownership evidence.
- [ ] Retire any candidate that duplicates CWE, PERF, `go vet`, staticcheck, errcheck, bodyclose, or sqlclosecheck without a documented additional value.

### 4.2 Optional high-risk performance work

- [ ] Profile with `cargo flamegraph` or `perf record` on the release binary only if Phase 1 identifies a reproducible bottleneck.
- [ ] Evaluate shared parse/fact reuse across PERF, CWE, and BP with cache-invalidation and ownership measurements.
- [ ] Evaluate small-`--only` fact-builder skipping, package method-set memoization, and dispatch needle batching only against a preserved finding oracle.
- [ ] Do not pursue on-disk tree retention/incremental tree-sitter reparse unless the CLI memory/speed trade-off is measured and accepted.

### 4.3 Advanced taint capability boundaries

- [ ] Decide whether prepared-statement same-variable parameterization, decoder output pointers, external-package propagation, and channel/goroutine handoffs justify typed Go facts or stronger data-flow infrastructure.
- [ ] If approved, design the conservative false-negative/false-positive contract before implementation; do not claim whole-program taint coverage.
- [ ] Keep the existing explicit false-negative model until the new contract has fixtures, integration tests, and representative-project validation.

### 4.4 Roadmap-only investments

- [ ] Consider optional `--typed` / `go/packages` support only after the PERF pack is trusted.
- [ ] Consider Python investment only with explicit funding and a new/reversed ADR, as required by the Go-first multi-language decision.

---

## Dependencies

- **Phase 1:** stable host-load observation, the gopdfsuit workload, release/perf-run binary, and the 943-finding oracle.
- **Phase 2:** `GoBadPracticeScan`, ruleset/dispatch/fixture manifest, representative Go modules, `go vet`, and staticcheck.
- **Phase 3:** approved real-repository samples and a documented finding-review rubric.
- **Phase 4:** an explicit issue/decision plus stronger static facts, data-flow infrastructure, or measured performance evidence where stated.

## Verification Baseline Recorded by This Audit

- [x] `make lint` passed (`cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`).
- [x] `cargo test --test go_taint_integration --locked` passed: 2 passed, 0 failed, 0 ignored.
- [x] No production `todo!`, `unimplemented!`, or ignored Rust tests were found during the source scan; documented capability ceilings are intentionally explicit rather than hidden work items.

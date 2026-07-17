# v0.0.5 — Pending Work Reconciliation Checklist

> **Parent:** `ROADMAP.md` — live 0.1.x product direction; this file is a one-time reconciliation snapshot for historical unchecked boxes, not a replacement roadmap.
> **Status:** Audit complete on 2026-07-17. Five current work outcomes are ready to manage; decision-gated work is explicitly separated.
> **Estimated effort:** 3–5 days for Phases 0–3, excluding external-repository pilots and any approved deferred capability.

---

## Overview

This checklist consolidates every Markdown `- [ ]` row currently present in the repository into a single, evidence-based management view. The scan found **741 raw unchecked boxes in 32 files**. Most are intentionally not current implementation work: archived plans, duplicated deferred snapshots, research candidate lists, PR templates, or struck/skipped rows.

The purpose of this document is to prevent historical plan text from being mistaken for an active release commitment. Keep `ROADMAP.md` and GitHub issues as the product source of truth; use this file to close, defer, or promote the surviving outcomes with evidence.

---

## Executive Summary

- The only required unfinished performance work is reproducing the reported **462.7 ms** normal-workflow cold scan using the exact `make run` command and a host-load record. The implementation and the controlled no-cache measurement are already complete.
- The active detector work is quality work, not catalog expansion: audit the noisiest existing BP rules, add safe near-miss coverage, label review-only limits, and run real-module canaries against `go vet` / staticcheck.
- Recommended-pack product trust still needs a real-repository pilot, long-tail CWE maturity review, and continued NEEDLES hygiene. These are follow-on product evidence, not a reason to add every historical proposed rule.
- Advanced taint modelling, 29 absent BP candidates, optional performance micro-optimizations, typed Go facts, and Python investment remain **decision-gated**. They must not be started merely because an old document contains an unchecked box.

**Success criteria:** every active outcome has a reproducible validation result and an explicit disposition; no archival checklist remains implicitly presented as live work; `ROADMAP.md` and `CHANGELOG.md` are updated when a shipped decision affects product scope.

---

## Phase 0: Establish One Auditable Backlog

### 0.1 Preserve the audit boundary

- [ ] Record the Phase 1–3 decisions in the owning source documents and update `ROADMAP.md` whenever a decision changes 0.1.x scope.
- [ ] For each archived source below, mark its surviving outcome as completed, deferred, or superseded only after source/test evidence is attached; do not bulk-check historical rows.
- [ ] Remove the stale claim that Go taint integration tests are ignored and correct the stale IP-007/IP-008 deferred manifest comment. The current integration test already runs two tests with no ignored cases.
- [ ] Keep `plans/v0.0.5/pending-work.md` as this reconciliation snapshot; create an issue for any item selected for implementation.

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

---

## Phase 1: Close the Cold-Scan Acceptance Gate

### 1.1 Reproduce the normal workflow

- [ ] Capture the exact command, `RUN_PROFILE`, `RUN_ARGS`, CodeHound revision, gopdfsuit revision/path, CPU governor/power mode, competing load, and cache state for the reported 462.7 ms run.
- [ ] Run a ten-sample normal-workflow comparison using the same `make run` target; report min, p50, p95, max, and the full-summary wall time rather than JSON-only timing.
- [ ] Compare the measurement with the established zero-cache oracle: 943 findings/fingerprints and the controlled `make run SKIP_BUILD=1 RUN_ARGS='--no-cache'` 272 ms p50 baseline.
- [ ] Classify the 462.7 ms observation as reproducible regression, expected host/workload variance, or a command/profile mismatch; attach the raw samples and host-load record.
- [ ] Update the v0.0.4 performance record and `ROADMAP.md` only after the classification is evidenced.

### 1.2 Guard semantic correctness

- [ ] Preserve a before/after finding multiset and fingerprint comparison for the gopdfsuit scan before accepting any performance change.
- [ ] Run focused PERF/BP integration coverage, `make test`, and `make lint` for any code change made during the investigation.

---

## Phase 2: Make the Bad-Practice Pack Trustworthy

### 2.1 Audit existing-pack precision

- [ ] BP-1: retain conservative discard shapes and document the typed/variant limitation instead of widening every ignored call.
- [ ] BP-6: test nested blocks and multiple goroutines for duplicate or misplaced findings.
- [ ] BP-8: prove the same mutex object is implicated; reject file-level co-presence.
- [ ] BP-9: test matching around nested braces, comments, and strings.
- [ ] BP-12 and BP-14: label as heuristic/review-only unless local ownership/cancellation evidence proves otherwise.
- [ ] BP-46..BP-55: audit project-level lifecycle findings for intent-dependent false positives.
- [ ] BP-56..BP-65: keep module/dependency findings distinct from source-level BP output and keep BP-63 reserved.

### 2.2 Document and validate the boundaries

- [ ] Add an explicit “review required” note for every rule that cannot prove required type or control-flow facts.
- [ ] Reconcile stale v0.0.2 BP pending-work wording with the shipped BP-1..BP-65 implementation, without rewriting historical evidence.
- [ ] Add or tighten a vulnerable fixture, safe near-miss fixture, and structural/identifier variant for each detector changed in 2.1.
- [ ] Run `cargo test --test go_bad_practice_integration` after each changed detector, then `make test` and `make lint` for the phase.
- [ ] Record changed false-positive/false-negative behavior before considering another BP catalog expansion.

### 2.3 Test in representative modules

- [ ] Scan a clean small Go library and classify every recommended/BP finding; no unexplained recommended findings may remain.
- [ ] Scan a representative HTTP service to exercise framework-gated BP behavior.
- [ ] Compare changed findings with `go vet` and staticcheck; document duplicate, narrower, and CodeHound-specific outcomes.

---

## Phase 3: Establish Recommended-Pack Product Trust

### 3.1 Run the real-repository pilot

- [ ] Triage a senior-reviewed sample of about 20 recommended-pack findings from real Go repositories and measure whether at least 70% are actionable.
- [ ] Publish the sample criteria, repository revisions, rule IDs, finding disposition, and actionability calculation; do not use fixture-only results.
- [ ] Use failures from the pilot to narrow, quarantine, re-tier, or remove rules rather than adding compensating rules.

### 3.2 Continue catalog honesty

- [ ] Audit the CWE long-tail needles and expand the maturity table from evidence.
- [ ] Define and enforce the rewrite bar before promoting a rule to `structural` maturity.
- [ ] Prefer call facts and callee classification over `SourceIndex.has` as the primary detector signal where the currently selected rule proves that feasible.
- [ ] Use NEEDLES as negative gates where possible and complete the remaining NEEDLES-comment pass incrementally.
- [ ] Track canary hit rates and create a dated deletion/review decision for rules with zero useful hits.

---

## Phase 4: Decision-Gated and Explicitly Deferred Work

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

# v0.0.3 — Curated Go Bad-Practice Implementation Checklist

> **Parent:** [`plans/v0.0.3/`](../README.md)
> **Status:** Phase 0 complete; first curated tranche and four domain batches integrated; next candidates pending
> **Decision:** Do not ship BP-66..BP-165 as 100 equal-status rules. Admit only high-signal, project-agnostic rules that survive the overlap and fixture gates below.
> **Estimated effort:** 4–6 weeks for the curated first release; the remaining proposals stay deferred until evidence justifies them.

---

## Overview

This is the execution checklist for the recommendation made after auditing the existing BP-1..BP-65 implementation and the v0.0.3 BP-66..BP-165 proposal.

The existing pack remains an optional advisory pack. The new work is deliberately reduced to small vertical slices prepared in parallel by domain batch, then promoted one rule at a time through the shared integration gate.

The source sketches in `01-part-a-core-language.md` through `06-part-f-testing-api-hygiene.md` remain research material. This file is the shipping gate and the current status source of truth.

---

## Executive Summary

- [x] Confirm the pre-tranche baseline contained BP-1..BP-65 and no BP-66+ entries.
- [x] Confirm all current BP IDs are registered in the detector dispatch table.
- [x] Confirm the current BP integration suite passes before extending the catalog.
- [x] Keep BP disabled in `recommended`, `perf`, and `security`; keep it advisory in `style`.
- [x] Separate existing rules into trusted correctness, review-required heuristic, style/opinion, and reserved tiers.
- [ ] Harden or quarantine the noisiest existing detectors before broadening the catalog.
- [ ] Admit new rules only after overlap, static-provability, fixture, and canary gates pass.
- [x] Ship the first curated tranche of 16 rules, prepared in domain batches and promoted one vertical slice at a time.
- [ ] Reassess the deferred BP-66..BP-165 proposals using evidence from real modules before adding more.

### Success criteria

- No new rule is enabled by default in the recommended profile.
- Every shipped rule has a precise canonical fix and a safe near-miss fixture.
- Rules duplicated by `go vet`, staticcheck, errcheck, bodyclose, sqlclosecheck, or CWE are dropped, narrowed, or explicitly documented as framework-specific additions.
- `cargo test --test go_bad_practice_integration` stays green after every slice.
- No rule is promoted based only on one synthetic fixture.

---

## Phase 0: Baseline and policy lock

### 0.1 Current-state audit

- [x] Baseline count before this tranche: 65 rules and 65 dispatch entries.
- [x] Current count after this tranche: 81 rules and 81 dispatch entries.
- [x] Current fixture inventory includes 168 BP fixture files; project-level rules remain covered by their existing project fixtures.
- [x] Run `cargo test --test go_bad_practice_integration`: 12 passed, 0 failed.
- [x] Confirm BP-63 remains reserved for the curated advisory snapshot and is not treated as live vulnerability intelligence.

### 0.2 Existing-pack tiering

| Tier | Current rules | Policy |
|------|---------------|--------|
| Trusted correctness | BP-6, BP-7, BP-8, BP-9, BP-15 | Keep available in `style`; medium/low severity; still review detector precision. |
| Useful but review-required | BP-1, BP-4, BP-5, BP-10, BP-11, BP-12, BP-13, BP-14, BP-16..BP-20, BP-22..BP-27, BP-32..BP-38, BP-43, BP-44, BP-46..BP-61, BP-64, BP-65 | Keep advisory; do not fail ordinary CI by default. |
| Style/opinion | BP-2, BP-3, BP-21, BP-28..BP-31, BP-39..BP-42, BP-45, BP-62 | `info` or low; off by default where the current policy already says so. |
| Reserved | BP-63 | Keep quarantined until a real advisory feed exists. |

- [x] Record the tiering decision in `documents/bad-practices.md`.
- [ ] Add an explicit “review required” note to rules whose detector cannot prove type or control-flow facts.
- [ ] Reconcile the stale v0.0.2 pending-work status with the shipped BP-1..BP-65 code.

### 0.3 Profile contract

- [x] `recommended`, `perf`, and `security`: BP off.
- [x] `style` / `bp`: BP on as advisory, with BP-21 and BP-28 default-off.
- [x] `all`: full catalog, but findings remain subject to severity policy.
- [x] Keep all BP-66+ additions outside default recommended/security packs; the new rules remain advisory.

---

## Phase 1: Existing-pack trust cleanup

### 1.1 Detector precision audit

- [ ] BP-1: retain the conservative discard shapes; add a typed/variant limitation note rather than widening it to every ignored call.
- [ ] BP-6: verify nested blocks and multiple goroutines do not produce duplicate or misplaced findings.
- [ ] BP-8: require the same mutex object to be implicated; reject file-level co-presence.
- [ ] BP-9: validate block matching around nested braces, comments, and strings.
- [ ] BP-12/BP-14: label them heuristic and review-only unless local evidence proves ownership/cancellation.
- [ ] BP-46..BP-55: review project-level lifecycle findings for intent-dependent false positives.
- [ ] BP-56..BP-65: keep module/dependency findings separate from source-level BP output; BP-63 remains reserved.

### 1.2 Existing-pack validation

- [ ] Add or tighten safe near-miss fixtures for every detector changed in 1.1.
- [ ] Run the focused BP integration suite after each detector change.
- [ ] Run the full Rust test suite after Phase 1.
- [ ] Review the changed existing-pack behavior before starting BP-66+ work.

---

## Phase 2: New-rule admission gate

Every proposed BP-66+ rule must pass all gates before implementation.

### 2.1 Gate checklist per rule

- [ ] The rule is not already covered by BP-1..BP-65, CWE, PERF, `go vet`, staticcheck, errcheck, bodyclose, sqlclosecheck, or a standard golangci-lint check.
- [ ] If it overlaps a tool, the rule adds a clearly documented framework, lifecycle, or multi-statement value.
- [ ] The vulnerable pattern is statically provable with current tree-sitter/source facts; no invented type or interprocedural certainty.
- [ ] The canonical fix fits in one actionable sentence.
- [ ] A vulnerable `.txt` fixture and a safe near-miss `.txt` fixture can be written before detector code.
- [ ] The rule has an expected severity and default profile.
- [ ] The rule has a suppression/intent boundary for legitimate uses.
- [ ] The rule is tested against at least one renamed or structurally varied fixture before promotion.
- [ ] The rule is checked against one real or representative multi-file module when framework/project context matters.

### 2.2 Rejection/defer policy

- [ ] Drop exact duplicates instead of adding a CodeHound-branded copy.
- [ ] Defer rules requiring full `go/types`, SSA, race detection, or runtime configuration unless a conservative local subset is demonstrably useful.
- [ ] Defer architecture preferences such as mandatory middleware, logging library choice, namespace conventions, and interface shape.
- [ ] Move true security vulnerabilities to CWE rather than creating BP duplicates.
- [ ] Keep framework rules import-gated and never fire on a generic method-name match alone.

---

## Phase 3: Curated first tranche — prepare by batch, promote by rule

Target: approximately 15 rules. The order is intentional: high-impact correctness first, then framework/data lifecycle rules with clear import gates.

### 3.1 Core language and context

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 1 | BP-73 — nil map write without initialization | Admit only for function-local zero-value maps with a proven write before `make`. | **Shipped** |
| 2 | BP-72 — typed nil interface return | Admit only when the return type is visibly an interface/error and the nil pointer flows directly to return. | **Shipped** |
| 3 | BP-79 — context cancellation not released | Admit only for locally bound cancel functions with no call/defer in the same function. | **Shipped — review-only** |
| 4 | BP-84 — integer percentage truncation | Admit only for the exact integer `/` then `* 100` shape; keep low severity. | **Shipped** |
| 5 | BP-67 — `errors.As` target not passed by address | Admit only for the exact stdlib call shape with a visibly non-address target. | **Shipped** |
| 6 | BP-75 — copy into zero-length slice | Admit only for a local statically zero-length destination and non-empty literal source. | **Shipped — low advisory** |
| 7 | BP-80 — `context.TODO` in production | Admit only for exact calls outside test files; keep low advisory severity. | **Shipped — low advisory** |
| 8 | BP-85 — unchecked type assertion | Defer until an untrusted-boundary heuristic is defined; do not flag all assertions. | Deferred gate |

### 3.2 Standard-library HTTP and lifecycle

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 9 | BP-101 — response header written after body | Admit with `http.ResponseWriter`-shaped handler evidence. | **Shipped** |
| 10 | BP-102 — error path without HTTP status | Admit only when handler/error-path evidence is explicit. | Pending |
| 11 | BP-108 — handler uses `context.Background` | Fold into existing BP-13 unless the handler-specific evidence is materially better. | Deferred gate |
| 12 | BP-155 — unbounded JSON request body | Admit only for HTTP decode paths with no size limit; review CWE overlap. | Pending |

### 3.3 Framework correctness

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 13 | BP-109 — Gin error response without abort/return | Admit as a Gin-specific control-flow rule. | **Shipped** |
| 11 | BP-111 — Gin context used in goroutine without `Copy` | Admit only with import gate and resolve PERF overlap first. | Pending |
| 15 | BP-116 — Echo response/error double handling | Admit only when the same handler visibly writes and returns a second response path. | **Shipped** |
| 13 | BP-119 — Fiber context captured across goroutine | Admit only with import gate and captured-context evidence. | Pending |

### 3.4 Data and API lifecycle

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 14 | BP-136 — GORM `AutoMigrate` in request path | Admit only in handler-shaped functions and with GORM import evidence. | Pending |
| 15 | BP-142 — sqlx `In` without `Rebind` | Admit only when the expanded query reaches a sqlx execution call in the same function. | Pending |
| 19 | BP-145 — pgx pool connection not released | Admit only for a locally acquired connection with no release/close path. | **Shipped — review-only** |
| 17 | BP-165 — constructor starts lifecycle without close contract | Defer until multi-file type/method evidence is reliable; likely review-only. | Deferred gate |

#### BP-73 completed evidence

- [x] Admission boundary documented: function-local zero-value map only; parameters and initialized maps are safe.
- [x] Vulnerable fixture added: `BP-73-vulnerable.txt`.
- [x] Safe near-miss fixture added: `BP-73-safe.txt`.
- [x] Identifier-variant vulnerable/safe fixtures added.
- [x] JSON metadata and generated fix text added.
- [x] Detector registered in the existing BP dispatch seam.
- [x] `cargo test --test go_bad_practice_integration` passed: 12 tests.
- [x] Fixture manifest integration passed.
- [x] `--explain BP-73` returns the new metadata and fix.

#### BP-72, BP-79, BP-84, and BP-101 completed evidence

- [x] Each candidate passed a narrow admission review and has a documented overlap boundary.
- [x] Each candidate has vulnerable and safe `.txt` fixtures; BP-84 and BP-101 also have identifier/shape variants.
- [x] Each candidate has a dedicated detector module with no shared-file worker edits.
- [x] Shared metadata, dispatch, manifest, and documentation integration completed centrally.
- [x] Each candidate remains outside the recommended/perf/security default packs.
- [x] Run the full BP integration suite: 12 tests passed with all positive and safe fixtures.
- [x] Complete the personal review of these detectors; review-only boundaries are recorded in metadata and docs.

#### Batch promotion evidence: BP-67, BP-75, BP-80, BP-88, BP-98, BP-99, BP-109, BP-116, BP-131, BP-145, and BP-159

- [x] Four workers reviewed disjoint domain batches without touching shared catalog files.
- [x] Accepted candidates were narrowed to static, fixture-backed patterns; overlap-heavy and path-sensitive proposals were deferred.
- [x] Shared JSON metadata, fix text, dispatch, module exports, fixture manifest, and docs were integrated centrally.
- [x] Every promoted candidate has vulnerable, safe, and variant fixture coverage.
- [x] `cargo test --test go_bad_practice_integration` passed: 12 tests, 0 failures, 168 BP fixtures exercised.
- [x] Rust formatting and `git diff --check` pass for the promoted detector changes.
- [x] BP-98, BP-131, and BP-145 are explicitly review-only/import- or type-gated heuristics in metadata/docs.

#### Promoted domain-batch rows

| Batch | Rule | Status |
|------|------|--------|
| Concurrency/resources | BP-88 — nil channel send/receive | **Shipped** |
| Concurrency/resources | BP-98 — opened file without close/transfer | **Shipped — review-only** |
| Concurrency/resources | BP-99 — `sync.Cond.Wait` without locker | **Shipped** |
| Data/configuration | BP-131 — Query for literal DML without rows | **Shipped — review-only** |
| Data/configuration | BP-159 — flag value read before parse | **Shipped** |

### 3.6 Parallel batch ownership

Workers may prepare independent domain batches in parallel. They must not edit shared dispatch, ruleset metadata, fixture manifest, documentation, or this checklist. The coordinator owns integration, promotion, and final validation.

| Batch | Scope | Worker ownership | Current status |
|------|-------|------------------|----------------|
| A | Core language and context: BP-72, BP-73, BP-79, BP-84, BP-85 and nearby candidates | Core-language detector modules and their `.txt` fixtures | First batch integrated; next candidate triage pending |
| B | Concurrency and resources: BP-86..BP-100 | Concurrency/resource detector module(s) and their `.txt` fixtures | Batch integrated; next candidate triage pending |
| C | HTTP and frameworks: BP-101..BP-125 | HTTP/framework detector module(s) and their `.txt` fixtures | Batch integrated; next candidate triage pending |
| D | Data, observability, and API lifecycle: BP-126..BP-165 | Data/API detector module(s) and their `.txt` fixtures | Batch integrated; next candidate triage pending |

- [x] Define disjoint worker ownership for detector modules and fixture files.
- [x] Keep shared integration centralized: JSON, dispatch, manifest, docs, checklist, and release-gate commands.
- [x] Launch the four workers against batches A–D rather than isolated single-rule tasks.
- [x] Review each worker's accepted/deferred candidate list and integrate only rules that pass the admission gate.
- [x] Promote admitted candidates individually after their own vulnerable, safe, variant, and focused CLI checks pass.

### 3.5 Per-rule vertical slice

For each future admitted rule, complete these in order before moving to the next row:

- [ ] Write the rule-specific admission note and overlap decision.
- [ ] Add the failing vulnerable `.txt` fixture.
- [ ] Add the safe near-miss `.txt` fixture.
- [ ] Add any required project fixture using the existing project-fixture convention.
- [ ] Add the JSON metadata entry and generated metadata/fix text.
- [ ] Implement the smallest detector at the existing BP seam.
- [ ] Register the detector in dispatch and add only needed SourceIndex prefilters.
- [ ] Add/extend the rule-specific integration assertion.
- [ ] Run `cargo test --test go_bad_practice_integration`.
- [ ] Run a focused CLI scan of the vulnerable and safe fixture.
- [ ] Mark the rule shipped only when both positive and negative cases pass.

---

## Phase 4: Deferred candidate review

- [ ] Review BP-66, BP-68, BP-69, BP-70, BP-71 against existing error tooling before any implementation.
- [ ] Review BP-77, BP-78, BP-81, BP-82, BP-83 against staticcheck/contextcheck and PERF overlap.
- [ ] Review BP-86..BP-100 for control-flow feasibility; reject rules that need race detection or whole-program ownership.
- [ ] Review BP-103, BP-106, BP-118, BP-129, BP-139, BP-146, and BP-152 for CWE ownership.
- [ ] Review BP-110, BP-117, BP-120, BP-140, and BP-143 as framework-specific error-discard variants; keep only if they add context beyond BP-1/errcheck.
- [ ] Review BP-112, BP-113, BP-114, BP-121, BP-124, BP-125, BP-130, BP-144, BP-147, BP-148, BP-153, BP-157, and BP-160 as policy/intent rules; do not promote without real-user evidence.
- [ ] Record every dropped rule and replacement candidate rather than leaving unexplained holes.

---

## Phase 5: Verification and release gates

- [x] `cargo test --test go_bad_practice_integration` green.
- [x] Full `cargo test` green.
- [ ] `cargo fmt --check` green; existing unrelated import-order blockers remain in `src/engine/cache/mod.rs` and `src/engine/mod.rs`.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` green; existing `criterion::black_box` deprecation blockers remain in `benches/scan_throughput.rs`.
- [ ] Scan a clean small Go library: no unexpected recommended findings.
- [ ] Scan a representative HTTP service for framework-gated behavior.
- [ ] Compare changed findings with staticcheck/go vet output and document overlap.
- [x] Update `documents/bad-practices.md` for every shipped rule.
- [x] Update the v0.0.3 README and checklist counts from measured shipped IDs.
- [x] Personally review the completed slice; no review subagents were used.
- [x] Commit locally with an intentional BP-specific message; do not push unless separately requested.

---

## Dependencies

- Existing `GoBadPracticeScan` detector and dispatch table.
- Generated metadata from `ruleset/golang/bad-practices.json` and `build/gen_bp.rs`.
- Existing `.txt` fixture materialization and BP integration harness.
- Existing profile/config filtering for advisory BP output.
- Framework import gates and multi-file project fixtures for framework/data rules.
- `go vet`, staticcheck, errcheck, bodyclose, sqlclosecheck, and CWE overlap checks.

## Working rule

Prepare pending work in disjoint domain batches. Do not promote an individual rule until it has its detector, metadata, fixtures, focused tests, and synchronized checklist status. Shared integration remains centralized so parallel workers cannot silently change the catalog contract.

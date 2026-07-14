# v0.0.3 — Curated Go Bad-Practice Implementation Checklist

> **Parent:** [`plans/v0.0.3/`](../README.md)
> **Status:** Phase 4 batch integrated and validated; 100 BP rules are implemented/registered, while 65 proposed BP-66..BP-165 candidates remain unimplemented or explicitly deferred
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

- [x] No new rule is enabled by default in the recommended profile.
- [x] Every shipped rule has a precise canonical fix and a safe near-miss fixture.
- [x] Rules duplicated by `go vet`, staticcheck, errcheck, bodyclose, sqlclosecheck, or CWE were dropped, narrowed, or explicitly documented as framework-specific additions.
- [x] `cargo test --test go_bad_practice_integration` stays green after every shipped slice.
- [x] No rule was promoted based only on one synthetic fixture; each shipped rule has variant coverage.

## Pending work now

- [ ] Complete the existing-pack trust cleanup in Phase 1, or explicitly record why each audit item remains deferred.
- [ ] Reconcile the stale v0.0.2 pending-work documentation with the current BP-1..BP-65 implementation.
- [x] Decide whether to admit BP-102, BP-111, BP-119, BP-136, and BP-142 after fresh overlap and fixture review; BP-102, BP-136, and BP-142 shipped, while BP-111/BP-119 remain deferred due PERF overlap.
- [ ] Revisit deferred-gate candidates BP-108, BP-155, and BP-165 only when stronger static proof is available.
- [ ] Resolve the 65 proposed BP-66..BP-165 candidates that are not present in the live ruleset/dispatch, either by implementing them through the admission gate or explicitly retiring them.
- [x] Complete the remaining Phase 4 candidate reviews and record dropped/replacement candidates.
- [x] Resolve the repository-wide `cargo fmt --check` blockers in `src/engine/cache/mod.rs` and `src/engine/mod.rs`.
- [x] Resolve the repository-wide Clippy blocker from deprecated `criterion::black_box` in `benches/scan_throughput.rs`.
- [ ] Run clean-library and representative-HTTP canary scans, then compare new findings with `go vet`/staticcheck output.
- [x] Select and launch five disjoint next-domain batches after the next candidate set was approved.
- [x] Review the five worker reports and personally audit each accepted detector.
- [x] Centrally integrate only admitted candidates into ruleset metadata, dispatch, manifest, docs, and this checklist.
- [x] Run focused BP fixtures, full Rust tests, and update this checklist with the batch result.
- [x] Run `make lint` and `make fmt`; clippy, rustfmt, and the benchmark lint gate are now green.
- [x] Select and launch the next disjoint Phase 4 candidate batches.
- [x] Review the five Phase 4 worker reports and personally audit accepted rules.
- [x] Centrally integrate only Phase 4 admissions after overlap and fixture gates pass.
- [x] Update the checklist with Phase 4 shipped/deferred results and rerun the release tests.

---

## Phase 0: Baseline and policy lock

### 0.1 Current-state audit

- [x] Baseline count before this tranche: 65 rules and 65 dispatch entries.
- [x] Current count after the first tranche: 81 rules and 81 dispatch entries.
- [x] Current count after the previous batch: 89 rules and 89 dispatch entries.
- [x] Current count after Phase 4 promotion: 100 rules and 100 dispatch entries.
- [x] Current fixture inventory includes 256 BP fixture files; project-level rules remain covered by their existing project fixtures.
- [x] Run `cargo test --test go_bad_practice_integration`: 12 passed, 0 failed.
- [x] Confirm BP-63 remains reserved for the curated advisory snapshot and is not treated as live vulnerability intelligence.

### 0.1.1 Ruleset-to-plan implementation audit

- [x] Confirm the live `ruleset/golang/bad-practices.json` contains 100 rules.
- [x] Confirm all 100 live rules have matching detector dispatch entries.
- [x] Confirm the live BP catalog is numerically ordered by rule ID.
- [ ] Implement or explicitly retire the following 65 proposed rules; these IDs are present in the v0.0.3 planning material but are not present in the live ruleset or dispatch.

#### Core language/context — 10 unimplemented

- [ ] BP-69 — Returning Data With Non-Nil Error (Unclear Contract)
- [ ] BP-70 — Logging Error Then Continuing Without Return
- [ ] BP-71 — Ignoring Non-Error Multi-Return Values That Affect Correctness
- [ ] BP-74 — Slice Append Alias Unexpected Share
- [ ] BP-76 — Range Over Map With Deterministic-Order Assumption
- [ ] BP-77 — Context Value Used For Optional Parameters (Stringly Keys)
- [ ] BP-78 — Context Not Propagated To Child Call
- [ ] BP-81 — Repeated `time.Now` Comparisons Nested In Expressions
- [ ] BP-82 — Parsing Time Without Location (Ambiguous Local)
- [ ] BP-83 — Sleeping For Synchronization Outside Tests

#### Concurrency/resources — 9 unimplemented

- [ ] BP-90 — Range Over Channel Without Exit Condition In Non-Range Form
- [ ] BP-91 — Notification Channel Carrying Data Unnecessarily
- [ ] BP-92 — `errgroup.Group` Without Context (`WithContext`)
- [ ] BP-93 — `errgroup.Go` Closure Ignoring Returned Error Path
- [ ] BP-94 — Fire-And-Forget Goroutine Writing To Shared Map Without Sync
- [ ] BP-95 — `http.Response.Body` Not Closed (Client)
- [ ] BP-96 — `sql.Rows` / `sql.Row` Resource Not Closed
- [ ] BP-97 — Flushable Writer Never Flushed Before Read Side
- [ ] BP-100 — Goroutine Per Request Without Bound (Unbounded Fan-Out)

#### HTTP/frameworks — 18 unimplemented

- [ ] BP-103 — Redirect Using Unvalidated External URL
- [ ] BP-104 — `ServeHTTP` Mux Registered With Method-Insensitive Overlap Ambiguity
- [ ] BP-105 — Cookie Set Without `Secure`/`HttpOnly` In Non-Dev
- [ ] BP-106 — CORS Allow-Origin Reflects Request Origin Unconditionally
- [ ] BP-107 — Middleware Not Calling `next` / `Handler.ServeHTTP`
- [ ] BP-108 — Request Context Ignored After Server Shutdown Pattern
- [ ] BP-111 — Gin Goroutine Using `*gin.Context` Without `c.Copy()`
- [ ] BP-112 — Gin Route Group Missing Auth Middleware On Sensitive Prefix
- [ ] BP-113 — Gin Default Mode Not Set To Release In `main`
- [ ] BP-114 — Gin Trusting `ClientIP` Without Trusted Proxies Config
- [ ] BP-115 — Gin Binding Struct Missing `binding:"required"` On Critical Fields
- [ ] BP-118 — Echo Path Param Used In File Path Without Clean
- [ ] BP-119 — Fiber Context Lifetime Misuse Across Goroutine
- [ ] BP-121 — Fiber Prefork Enabled Without Caution In 12-factor Deploy
- [ ] BP-122 — Chi Middleware Chain Missing `next.ServeHTTP`
- [ ] BP-123 — Chi URLParam Used Without Presence Check Before Authz
- [ ] BP-124 — Panic Recovery Middleware Disabled/Missing On Public Server
- [ ] BP-125 — Mixing Framework Context With stdlib `http.ResponseWriter` Incorrectly

#### Data persistence — 14 unimplemented

- [ ] BP-126 — Transaction Without Commit/Rollback Handling
- [ ] BP-127 — Nested Transactions Assumed Supported
- [ ] BP-128 — `QueryRow` Scan Error Not Distinguished From `ErrNoRows`
- [ ] BP-129 — SQL String Built With `fmt.Sprintf` (Correctness/Injection Hygiene)
- [ ] BP-130 — `db.SetMaxOpenConns` Never Configured For Service Binary
- [ ] BP-132 — Ignoring `RowsAffected` When Required For Correctness
- [ ] BP-133 — GORM Error Not Checked After Chain
- [ ] BP-134 — GORM `First` Without `ErrRecordNotFound` Handling
- [ ] BP-135 — GORM Global `DB` Mutable Without Session
- [ ] BP-137 — GORM Soft-Delete Confusion (`Unscoped` Missing On Hard Delete Intent)
- [ ] BP-139 — GORM Raw SQL With String Concatenation
- [ ] BP-140 — sqlx `StructScan` / `Get` Error Ignored
- [ ] BP-143 — Redis Command Error Ignored
- [ ] BP-144 — Redis Key Without Namespace Prefix In Shared Instance

#### Observability/config/JSON/gRPC/CLI — 13 unimplemented

- [ ] BP-146 — Logging Sensitive Fields (Password/Token) At Info
- [ ] BP-147 — `log.Printf` Without Structured Logger In Service Code
- [ ] BP-148 — slog Handler Misconfigured With Debug Level In Production
- [ ] BP-149 — Error Logged Without `err` Attribute
- [ ] BP-150 — `os.Getenv` Without Default Or Empty Check For Required Config
- [ ] BP-152 — Hardcoded Localhost Credentials In Non-Test Code
- [ ] BP-153 — Config Parsed With `json.Unmarshal` Ignoring Critical Unknown Fields
- [ ] BP-154 — `json.Unmarshal` Error Ignored
- [ ] BP-155 — JSON Decoder Used On Unbounded Request Body Without Limit
- [ ] BP-156 — Relying On `omitempty` For Security-Sensitive Zero Values
- [ ] BP-157 — gRPC Server Without Unary Interceptor For Logging/Auth
- [ ] BP-158 — gRPC Ignoring `status.FromError` / Returning Naked `err`
- [ ] BP-160 — Cobra `Run` Instead Of `RunE` Swallowing Errors

#### Testing/API lifecycle — 1 unimplemented

- [ ] BP-165 — Exported Constructor Missing Context Or Closer Cleanup Contract

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

Target: the first 16-rule tranche is shipped. The next rows remain pending or deferred until they pass the same admission gate.

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
| 8 | BP-85 — unchecked type assertion | Admit only for typed net/http handlers reading request context values; do not flag all assertions. | **Shipped — boundary-gated** |

### 3.2 Standard-library HTTP and lifecycle

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 9 | BP-101 — response header written after body | Admit with `http.ResponseWriter`-shaped handler evidence. | **Shipped** |
| 10 | BP-102 — error path without HTTP status | Admit only when handler/error-path evidence is explicit. | **Shipped — handler-gated** |
| 11 | BP-108 — handler uses `context.Background` | Fold into existing BP-13 unless the handler-specific evidence is materially better. | Deferred gate |
| 12 | BP-155 — unbounded JSON request body | Admit only for HTTP decode paths with no size limit; review CWE overlap. | Pending |

### 3.3 Framework correctness

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 13 | BP-109 — Gin error response without abort/return | Admit as a Gin-specific control-flow rule. | **Shipped** |
| 14 | BP-111 — Gin context used in goroutine without `Copy` | Admit only with import gate and resolve PERF overlap first. | Pending |
| 15 | BP-116 — Echo response/error double handling | Admit only when the same handler visibly writes and returns a second response path. | **Shipped** |
| 16 | BP-119 — Fiber context captured across goroutine | Admit only with import gate and captured-context evidence. | Pending |

### 3.4 Data and API lifecycle

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 17 | BP-136 — GORM `AutoMigrate` in request path | Admit only in handler-shaped functions and with GORM import evidence. | **Shipped — import/type-gated** |
| 18 | BP-142 — sqlx `In` without `Rebind` | Admit only when the expanded query reaches a sqlx execution call in the same function. | **Shipped — same-function review-only** |
| 19 | BP-145 — pgx pool connection not released | Admit only for a locally acquired connection with no release/close path. | **Shipped — review-only** |
| 20 | BP-165 — constructor starts lifecycle without close contract | Defer until multi-file type/method evidence is reliable; likely review-only. | Deferred gate |

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

#### Next-batch promotion evidence: BP-68, BP-85, BP-102, BP-136, BP-142, BP-151, BP-162, and BP-164

- [x] Five workers reviewed disjoint core, HTTP, data, observability, and testing/API batches without touching shared catalog files.
- [x] Accepted candidates were personally audited; BP-111, BP-119, BP-146, BP-147, BP-148, BP-149, BP-150, BP-152..BP-160 (except BP-151), BP-161, BP-163, and BP-165 were deferred for overlap, intent, or insufficient local proof.
- [x] BP-68, BP-85, BP-102, BP-136, BP-142, BP-151, BP-162, and BP-164 have detector modules, generated metadata, fix text, dispatch entries, documentation, manifest entries, and vulnerable/safe/variant fixture coverage.
- [x] Personally tightened BP-85 handler gating, BP-151 zap-call matching, BP-162 package-global extraction, and BP-102 AST/source fallback behavior during integration.
- [x] Focused BP and fixture-manifest integration passed: 12 BP tests and 3 manifest tests; all 200 BP fixture files exercised.
- [x] Full `cargo test` passed after updating the README BP count from 65 to the measured 89 registered rules.
- [x] No codebase-memory MCP was used for this batch.

#### Phase 4 promotion evidence: BP-66, BP-86, BP-87, BP-89, BP-110, BP-117, BP-120, BP-138, BP-141, BP-161, and BP-163

- [x] Five workers reviewed disjoint core, concurrency, HTTP, data, and observability/testing batches without touching shared catalog files.
- [x] Accepted candidates were personally audited; BP-86/BP-87 were narrowed to explicit mutex receiver/parameter types, BP-141 received a same-file struct fallback for parser shape variance, and fixture false positives were removed.
- [x] The 11 admitted rules have detector modules, JSON metadata, fix text, dispatch entries, documentation, manifest entries, and vulnerable/safe/variant fixture coverage.
- [x] Focused BP integration, fixture inventory, fixture manifest, and README count tests passed; all 256 BP fixture files were exercised by the manifest gate.
- [x] Full `cargo test` passed after the Phase 4 integration, including the library, integration, fixture, performance-smoke, and doctest suites.
- [x] `make lint`, `make fmt`, and `git diff --check` passed after the Phase 4 integration.
- [x] Remaining candidates were deferred where the worker could not prove ownership, control flow, intent, or framework specificity with the current static facts.
- [x] No codebase-memory MCP was used for this batch.

#### Phase 4 promoted domain-batch rows

| Batch | Rule | Status |
|------|------|--------|
| Core language/context | BP-66 — wrapped sentinel compared directly | **Shipped — review-only** |
| Concurrency/resources | BP-86 — mutex lock without visible unlock | **Shipped — review-only** |
| Concurrency/resources | BP-87 — `RLock` held across blocking operation | **Shipped — review-only** |
| Concurrency/resources | BP-89 — repeated unconditional channel close | **Shipped — review-only** |
| HTTP/frameworks | BP-110 — Gin bind error ignored | **Shipped — framework-gated** |
| HTTP/frameworks | BP-117 — Echo bind error ignored | **Shipped — framework-gated** |
| HTTP/frameworks | BP-120 — Fiber body-parser error ignored | **Shipped — framework-gated** |
| Data persistence | BP-138 — typed GORM hook performs direct network I/O | **Shipped — review-only** |
| Data persistence | BP-141 — sqlx named snake_case placeholder mismatches untagged fields | **Shipped — review-only** |
| Observability/testing | BP-161 — production DSN literal in test code | **Shipped — review-only** |
| Observability/testing | BP-163 — golden-file update writes without short-test guard | **Shipped — review-only** |

### 3.5 Parallel batch ownership

Workers may prepare independent domain batches in parallel. They must not edit shared dispatch, ruleset metadata, fixture manifest, documentation, or this checklist. The coordinator owns integration, promotion, and final validation.

| Batch | Scope | Worker ownership | Current status |
|------|-------|------------------|----------------|
| A | Core language/context: BP-66, BP-69..BP-83 pending candidates | Core-language detector module(s) and their `.txt` fixtures | BP-66 shipped; BP-69..BP-83 deferred |
| B | Concurrency and resources: BP-86..BP-100 | Concurrency/resource detector module(s) and their `.txt` fixtures | BP-86, BP-87, BP-89 shipped; BP-90..BP-97 and BP-100 deferred |
| C | HTTP and frameworks: BP-103..BP-125 pending candidates | HTTP/framework detector module(s) and their `.txt` fixtures | BP-110, BP-117, BP-120 shipped; remaining candidates deferred |
| D | Data persistence: BP-126..BP-145 pending candidates | Data detector module(s) and their `.txt` fixtures | BP-138, BP-141 shipped; remaining candidates deferred |
| E | Observability/config and remaining lifecycle tail: BP-146..BP-165 pending candidates | Observability/API/testing detector module(s) and their `.txt` fixtures | BP-161, BP-163 shipped; remaining candidates deferred |

- [x] Define disjoint worker ownership for detector modules and fixture files.
- [x] Keep shared integration centralized: JSON, dispatch, manifest, docs, checklist, and release-gate commands.
- [x] Launch the four workers against batches A–D rather than isolated single-rule tasks.
- [x] Launch five workers for the next core, HTTP, data, observability, and API/testing batches.
- [x] Review each worker's accepted/deferred candidate list and integrate only rules that pass the admission gate.
- [x] Promote admitted candidates individually after their own vulnerable, safe, variant, and focused CLI checks pass.

### 3.6 Per-rule vertical slice

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

- [x] Review BP-66 against existing error tooling; it is now shipped as a wrapped-sentinel comparison rule with a conservative error-name gate. BP-69, BP-70, BP-71, BP-74, BP-76, BP-77, BP-78, BP-81, BP-82, and BP-83 remain deferred.
- [x] Review BP-86, BP-87, and BP-89 for control-flow feasibility; they are shipped as review-only heuristics. BP-90..BP-97 and BP-100 remain deferred because they need stronger ownership or control-flow proof.
- [x] Review BP-110, BP-117, and BP-120 as framework-specific error-discard variants; they add explicit Gin, Echo, and Fiber import/context gates and are shipped. BP-103, BP-104..BP-107, BP-122..BP-125 remain deferred.
- [x] Review BP-138 and BP-141 for data-layer specificity; both are shipped as review-only rules. BP-126..BP-130, BP-132, BP-133..BP-135, BP-137, and BP-139..BP-144 remain deferred.
- [x] Review BP-161 and BP-163 as test/lifecycle hygiene rules; both are shipped as review-only rules. BP-146..BP-150, BP-152..BP-158, BP-160, and BP-165 remain deferred.
- [x] Record dropped or deferred candidates with the worker evidence rather than leaving unexplained holes; revisit them only after real-module canaries or stronger static proof.

---

## Phase 5: Verification and release gates

- [x] `cargo test --test go_bad_practice_integration` green.
- [x] Full `cargo test` green.
- [x] `cargo fmt --check` green after the cleanup commit.
- [x] `cargo clippy --all-targets --all-features -- -D warnings` green after switching the benchmark to `std::hint::black_box`.
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

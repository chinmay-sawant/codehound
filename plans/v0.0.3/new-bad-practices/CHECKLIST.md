# v0.0.3 — Curated Go Bad-Practice Implementation Checklist

> **Parent:** [`plans/v0.0.3/`](../README.md)
> **Status:** Deferred implementation batches integrated and validated; 136 BP rules are implemented/registered, while 29 proposed BP-66..BP-165 candidates remain explicitly deferred
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
- [x] Decide whether to admit BP-102, BP-111, BP-119, BP-136, and BP-142 after fresh overlap and fixture review; all five shipped with bounded framework/handler gates and documented PERF overlap boundaries.
- [ ] Revisit deferred-gate candidates BP-108 and BP-165 only when stronger static proof is available.
- [ ] Resolve the remaining 29 proposed BP-66..BP-165 candidates that are not present in the live ruleset/dispatch, either by implementing them through the admission gate or explicitly retiring them.
- [x] Rename the Phase 4 implementation modules to domain-specific filenames without `batch_phase4` naming.
- [x] Integrate the next accepted pending candidates from the five parallel domain batches.
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
- [x] Current count after the deferred-candidate promotion: 136 rules and 136 dispatch entries.
- [x] Current fixture inventory includes 368 BP fixture files; project-level rules remain covered by their existing project fixtures.
- [x] Run `cargo test --test go_bad_practice_integration`: 12 passed, 0 failed.
- [x] Confirm BP-63 remains reserved for the curated advisory snapshot and is not treated as live vulnerability intelligence.

### 0.1.1 Ruleset-to-plan implementation audit

- [x] Confirm the live `ruleset/golang/bad-practices.json` contains 136 rules.
- [x] Confirm all 136 live rules have matching detector dispatch entries.
- [x] Confirm the live BP catalog is numerically ordered by rule ID.
- [x] Classify all 29 remaining proposed rules that are absent from the live ruleset and dispatch as explicitly deferred, with evidence-based reasons recorded below.

#### Core language/context — 5 deferred

- [~] BP-69 — Returning Data With Non-Nil Error (Unclear Contract) — deferred: return-value intent is contract-dependent and not statically provable.
- [x] BP-70 — Logging Error Then Continuing Without Return — shipped; bounded `err != nil` plus standard-log and explicit-exit analysis.
- [~] BP-71 — Ignoring Non-Error Multi-Return Values That Affect Correctness — deferred: correctness impact requires type/call-site semantics unavailable to the detector.
- [~] BP-74 — Slice Append Alias Unexpected Share — deferred: aliasing and ownership require stronger data-flow/type evidence.
- [x] BP-76 — Range Over Map With Deterministic-Order Assumption — shipped
- [~] BP-77 — Context Value Used For Optional Parameters (Stringly Keys) — deferred: API intent and legitimate context-key usage are not statically distinguishable.
- [~] BP-78 — Context Not Propagated To Child Call — deferred: propagation requires interprocedural call and ownership evidence.
- [x] BP-81 — Repeated `time.Now` Comparisons Nested In Expressions — shipped
- [x] BP-82 — Parsing Time Without Location (Ambiguous Local) — shipped; literal layouts without zone directives only.
- [x] BP-83 — Sleeping For Synchronization Outside Tests — shipped; synchronization-shaped functions without visible coordination only.

#### Concurrency/resources — 0 deferred

- [x] BP-90 — Range Over Channel Without Exit Condition In Non-Range Form — shipped
- [x] BP-91 — Notification Channel Carrying Data Unnecessarily — shipped
- [x] BP-92 — `errgroup.Group` Without Context (`WithContext`) — shipped
- [x] BP-93 — `errgroup.Go` Closure Ignoring Returned Error Path — shipped
- [x] BP-94 — Fire-And-Forget Goroutine Writing To Shared Map Without Sync — shipped
- [x] BP-95 — `http.Response.Body` Not Closed (Client) — shipped as zero-dependency same-function coverage; bodyclose/sqlclosecheck overlap documented.
- [x] BP-96 — `sql.Rows` / `sql.Row` Resource Not Closed — shipped
- [x] BP-97 — Flushable Writer Never Flushed Before Read Side — shipped
- [x] BP-100 — Goroutine Per Request Without Bound (Unbounded Fan-Out) — shipped

#### HTTP/frameworks — 12 deferred

- [~] BP-103 — Redirect Using Unvalidated External URL — deferred: validation and trust-boundary intent require data-flow evidence beyond the current detector seam.
- [x] BP-104 — `ServeHTTP` Mux Registered With Method-Insensitive Overlap Ambiguity — shipped
- [x] BP-105 — Cookie Set Without `Secure`/`HttpOnly` In Non-Dev — shipped
- [~] BP-106 — CORS Allow-Origin Reflects Request Origin Unconditionally — deferred: framework/configuration context and security overlap require broader evidence.
- [x] BP-107 — Middleware Not Calling `next` / `Handler.ServeHTTP` — shipped
- [~] BP-108 — Request Context Ignored After Server Shutdown Pattern — deferred: overlaps BP-13 and needs lifecycle/control-flow evidence.
- [x] BP-111 — Gin Goroutine Using `*gin.Context` Without `c.Copy()` — shipped with exact Gin import/type and function-local goroutine gates; PERF overlap documented.
- [~] BP-112 — Gin Route Group Missing Auth Middleware On Sensitive Prefix — deferred: authentication intent requires whole-package route and middleware analysis.
- [~] BP-113 — Gin Default Mode Not Set To Release In `main` — deferred: deployment configuration is not statically inferable.
- [~] BP-114 — Gin Trusting `ClientIP` Without Trusted Proxies Config — deferred: trusted-proxy configuration requires runtime/environment evidence.
- [~] BP-115 — Gin Binding Struct Missing `binding:"required"` On Critical Fields — deferred: field criticality and validation intent are not statically provable.
- [~] BP-118 — Echo Path Param Used In File Path Without Clean — deferred: security/data-flow proof overlaps CWE and is unavailable at the current seam.
- [x] BP-119 — Fiber Context Lifetime Misuse Across Goroutine — shipped with exact Fiber import/type and function-local goroutine gates; PERF overlap documented.
- [~] BP-121 — Fiber Prefork Enabled Without Caution In 12-factor Deploy — deferred: deployment intent and operational constraints are not source-proven.
- [x] BP-122 — Chi Middleware Chain Missing `next.ServeHTTP` — shipped
- [~] BP-123 — Chi URLParam Used Without Presence Check Before Authz — deferred: authentication intent and presence requirements require whole-handler evidence.
- [~] BP-124 — Panic Recovery Middleware Disabled/Missing On Public Server — deferred: server exposure and middleware completeness require whole-package evidence.
- [~] BP-125 — Mixing Framework Context With stdlib `http.ResponseWriter` Incorrectly — deferred: correctness depends on framework control flow not proven by current syntax facts.

#### Data persistence — 6 deferred

- [x] BP-126 — Transaction Without Commit/Rollback Handling — shipped with local commit/rollback and ownership-transfer boundaries.
- [~] BP-127 — Nested Transactions Assumed Supported — deferred: driver/runtime semantics are not statically available.
- [x] BP-128 — `QueryRow` Scan Error Not Distinguished From `ErrNoRows` — shipped
- [~] BP-129 — SQL String Built With `fmt.Sprintf` (Correctness/Injection Hygiene) — deferred: overlaps CWE/SQL tooling and needs query/data-flow proof.
- [~] BP-130 — `db.SetMaxOpenConns` Never Configured For Service Binary — deferred: package-wide configuration absence and deployment intent are not locally provable.
- [x] BP-132 — Ignoring `RowsAffected` When Required For Correctness — shipped
- [x] BP-133 — GORM Error Not Checked After Chain — shipped
- [x] BP-134 — GORM `First` Without `ErrRecordNotFound` Handling — shipped
- [x] BP-135 — GORM Global `DB` Mutable Without Session — shipped
- [~] BP-137 — GORM Soft-Delete Confusion (`Unscoped` Missing On Hard Delete Intent) — deferred: hard-delete intent is application-specific.
- [~] BP-139 — GORM Raw SQL With String Concatenation — deferred: overlaps CWE/SQL injection analysis and needs query/data-flow proof.
- [x] BP-140 — sqlx `StructScan` / `Get` Error Ignored — shipped
- [x] BP-143 — Redis Command Error Ignored — shipped
- [~] BP-144 — Redis Key Without Namespace Prefix In Shared Instance — deferred: shared-instance and namespace intent require deployment/configuration evidence.

#### Observability/config/JSON/gRPC/CLI — 5 deferred

- [x] BP-146 — Logging Sensitive Fields (Password/Token) At Info — shipped
- [x] BP-147 — `log.Printf` Without Structured Logger In Service Code — shipped
- [~] BP-148 — slog Handler Misconfigured With Debug Level In Production — deferred: production configuration intent requires runtime/environment evidence.
- [x] BP-149 — Error Logged Without `err` Attribute — shipped
- [~] BP-150 — `os.Getenv` Without Default Or Empty Check For Required Config — deferred: requiredness and acceptable defaults are application-specific.
- [~] BP-152 — Hardcoded Localhost Credentials In Non-Test Code — deferred: security relevance and credential intent require context beyond local syntax.
- [~] BP-153 — Config Parsed With `json.Unmarshal` Ignoring Critical Unknown Fields — deferred: critical fields and compatibility policy are application-specific.
- [x] BP-154 — `json.Unmarshal` Error Ignored — shipped for direct expression statements; blank assignments remain covered by BP-1.
- [x] BP-155 — JSON Decoder Used On Unbounded Request Body Without Limit — shipped
- [x] BP-156 — Relying On `omitempty` For Security-Sensitive Zero Values — shipped
- [~] BP-157 — gRPC Server Without Unary Interceptor For Logging/Auth — deferred: runtime middleware/auth policy is not statically provable.
- [x] BP-158 — gRPC Ignoring `status.FromError` / Returning Naked `err` — shipped for gRPC-shaped methods with status/import gates.
- [x] BP-160 — Cobra `Run` Instead Of `RunE` Swallowing Errors — shipped as an advisory Cobra command-literal check.

#### Testing/API lifecycle — 1 deferred

- [~] BP-165 — Exported Constructor Missing Context Or Closer Cleanup Contract — deferred: reliable multi-file type, lifecycle, and ownership evidence is unavailable.

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

- [x] BP-1: retained the conservative discard shapes; documented the typed/variant limitation and added vulnerable/safe `os.Stat` variants without widening the heuristic.
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
| 12 | BP-155 — unbounded JSON request body | Admit only for HTTP decode paths with no size limit; review CWE overlap. | **Shipped** |

### 3.3 Framework correctness

| Order | Rule | Decision | Status |
|------:|------|----------|--------|
| 13 | BP-109 — Gin error response without abort/return | Admit as a Gin-specific control-flow rule. | **Shipped** |
| 14 | BP-111 — Gin context used in goroutine without `Copy` | Admit only with import gate and resolve PERF overlap first. | **Shipped** — import/type/function-local gate; PERF overlap documented. |
| 15 | BP-116 — Echo response/error double handling | Admit only when the same handler visibly writes and returns a second response path. | **Shipped** |
| 16 | BP-119 — Fiber context captured across goroutine | Admit only with import gate and captured-context evidence. | **Shipped** — import/type/function-local gate; PERF overlap documented. |

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
- [x] Historical overlap review deferred BP-111, BP-119, BP-146, BP-147, BP-148, BP-149, BP-150, BP-152..BP-160 (except BP-151), BP-161, BP-163, and BP-165; the later deferred-candidate batch promoted BP-111, BP-119, BP-154, BP-158, and BP-160 after bounded detector and fixture review.
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

#### Phase 5 promotion evidence: prior accepted rules from five parallel domain batches

- [x] Five workers reviewed disjoint core, concurrency, HTTP, data, and observability batches without touching shared catalog files; the old `batch_phase4_*` modules were renamed to domain-specific filenames before integration.
- [x] Accepted core rules: BP-76 and BP-81.
- [x] Accepted concurrency/resource rules: BP-90, BP-91, BP-92, BP-93, BP-94, BP-96, BP-97, and BP-100.
- [x] Accepted HTTP/framework rules: BP-104, BP-105, BP-107, and BP-122.
- [x] Accepted data-persistence rules: BP-128, BP-132, BP-133, BP-134, BP-135, BP-140, and BP-143.
- [x] Accepted observability/config/JSON rules: BP-146, BP-147, BP-149, BP-155, and BP-156.
- [x] Each admitted rule has detector code, generated metadata/fix text, dispatch registration, documentation, manifest ownership, and vulnerable/safe/variant fixture coverage.
- [x] The live catalog is 136 rules with 136 dispatch entries; the catalog remains numerically ordered and the README count matches the registry.
- [x] Focused fixture inventory, manifest, BP integration, and README-count tests passed; 368 BP fixture files are present on disk.
- [x] Detector fixes made during validation: Tree-sitter assignment ancestors are resolved through expression lists, duplicate ServeMux registrations are recognized, and safe fixtures remain isolated from existing BP/PERF rules.
- [x] No codebase-memory MCP was used; the completed batch was personally reviewed without review subagents.

#### Phase 5 deferred candidates

- [~] Core/context: BP-69, BP-71, BP-74, BP-77, and BP-78 remain deferred for unclear intent, aliasing, or insufficient local/static proof.
- [~] HTTP/frameworks: BP-103, BP-106, BP-108, BP-112, BP-113, BP-114, BP-115, BP-118, BP-121, BP-123, BP-124, and BP-125 remain deferred for security/tooling overlap, deployment/auth intent, whole-package evidence, or unprovable framework semantics.
- [~] Data persistence: BP-127, BP-129, BP-130, BP-137, BP-139, and BP-144 remain deferred for transaction ownership, CWE overlap, package-wide configuration, intent, or namespace semantics.
- [~] Observability/config/testing: BP-148, BP-150, BP-152, BP-153, BP-157, and BP-165 remain deferred for deployment/configuration intent, security overlap, or insufficient lifecycle/type evidence.

#### Deferred-candidate implementation batch evidence

- [x] Four disjoint batches were implemented with coordinator-owned shared integration: core, HTTP/framework, data persistence, and overlap/CLI.
- [x] Promoted BP-70, BP-82, BP-83, BP-95, BP-111, BP-119, BP-126, BP-154, BP-158, and BP-160.
- [x] Each promoted rule has detector code, generated metadata/fix text, dispatch registration, documentation, manifest ownership, and vulnerable/safe `.txt` fixtures.
- [x] `cargo test --test fixture_manifest_integration_manifest` passed with the full manifest.
- [x] `cargo test --test go_bad_practice_integration` passed: 12 tests, 0 failures.
- [x] `cargo test --test go_bad_practice_project_integration` passed.
- [x] `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check` passed.
- [x] The live catalog now contains 136 rules and 368 BP fixture files.

### 3.5 Parallel batch ownership

Workers may prepare independent domain batches in parallel. They must not edit shared dispatch, ruleset metadata, fixture manifest, documentation, or this checklist. The coordinator owns integration, promotion, and final validation.

| Batch | Scope | Worker ownership | Current status |
|------|-------|------------------|----------------|
| A | Core language/context: BP-66, BP-69..BP-83 pending candidates | Core-language detector module(s) and their `.txt` fixtures | BP-66, BP-76, BP-81 shipped; BP-70, BP-82, BP-83 promoted in the deferred batch; BP-69, BP-71, BP-74, BP-77, BP-78 deferred |
| B | Concurrency and resources: BP-86..BP-100 | Concurrency/resource detector module(s) and their `.txt` fixtures | BP-86, BP-87, BP-89, BP-90, BP-91, BP-92, BP-93, BP-94, BP-96, BP-97, BP-100 shipped; BP-95 promoted in the deferred batch |
| C | HTTP and frameworks: BP-103..BP-125 pending candidates | HTTP/framework detector module(s) and their `.txt` fixtures | BP-104, BP-105, BP-107, BP-110, BP-117, BP-120, BP-122 shipped; BP-111 and BP-119 promoted in the deferred batch; BP-103, BP-106, BP-108, BP-112, BP-113, BP-114, BP-115, BP-118, BP-121, BP-123, BP-124, BP-125 deferred |
| D | Data persistence: BP-126..BP-145 pending candidates | Data detector module(s) and their `.txt` fixtures | BP-128, BP-132, BP-133, BP-134, BP-135, BP-138, BP-140, BP-141, BP-143 shipped; BP-126 promoted in the deferred batch; BP-127, BP-129, BP-130, BP-137, BP-139, BP-144 deferred |
| E | Observability/config and remaining lifecycle tail: BP-146..BP-165 pending candidates | Observability/API/testing detector module(s) and their `.txt` fixtures | BP-146, BP-147, BP-149, BP-151, BP-155, BP-156, BP-161, BP-163 shipped; BP-154, BP-158, and BP-160 promoted in the deferred batch; BP-148, BP-150, BP-152, BP-153, BP-157, BP-165 deferred |

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

- [x] Review BP-66 against existing error tooling; it is now shipped as a wrapped-sentinel comparison rule with a conservative error-name gate. Phase 5 also shipped BP-76 and BP-81; the deferred batch promoted BP-70, BP-82, and BP-83, leaving BP-69, BP-71, BP-74, BP-77, and BP-78 deferred.
- [x] Review BP-86, BP-87, and BP-89 for control-flow feasibility; they are shipped as review-only heuristics. Phase 5 also shipped BP-90, BP-91, BP-92, BP-93, BP-94, BP-96, BP-97, and BP-100; the deferred batch promoted BP-95.
- [x] Review BP-110, BP-117, and BP-120 as framework-specific error-discard variants; they add explicit Gin, Echo, and Fiber import/context gates and are shipped. Phase 5 also shipped BP-104, BP-105, BP-107, and BP-122; the deferred batch promoted BP-111 and BP-119, leaving BP-103, BP-106, BP-108, BP-112, BP-113, BP-114, BP-115, BP-118, BP-121, BP-123, BP-124, and BP-125 deferred.
- [x] Review BP-138 and BP-141 for data-layer specificity; both are shipped as review-only rules. Phase 5 also shipped BP-128, BP-132, BP-133, BP-134, BP-135, BP-140, and BP-143; the deferred batch promoted BP-126, leaving BP-127, BP-129, BP-130, BP-137, BP-139, and BP-144 deferred.
- [x] Review BP-161 and BP-163 as test/lifecycle hygiene rules; both are shipped as review-only rules. Phase 5 also shipped BP-146, BP-147, BP-149, BP-155, and BP-156; the deferred batch promoted BP-154, BP-158, and BP-160, leaving BP-148, BP-150, BP-152, BP-153, BP-157, and BP-165 deferred.
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

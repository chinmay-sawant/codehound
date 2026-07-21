# v0.0.5 — Parallel Catalog Trust and Productization Program

> **Parent:** [`ROADMAP.md`](../../ROADMAP.md) and [`cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md)
> **Status:** Phase 0–1 complete (#95); Phase 2 executed (epic #105); Phase 3+ open
> **Estimated effort:** 4–6 issue-sized batches; do not schedule every phase at once

---

## Overview

This is the single execution ledger for the next CodeHound priorities after the
completed file-permissions tranche. It groups independent CWE catalog-trust
families into small parallel worktree batches, then reserves shared maturity,
profile, index, documentation, and release validation edits for one integration
branch.

The objective is not to maximize detector count. It is to make the shipped Go
catalog increasingly trustworthy, then use that evidence to improve the
user-facing rule experience. Every detector family must finish with an explicit
keep / quarantine / narrow / retire / structural-promotion decision.

---

## Executive Summary

The next three concrete catalog families are password storage, transport-secret
handling, and deserialization. They have discrete detector seams and can be
audited concurrently. The subsequent work is organized by existing domain
boundaries: access control, credential lifecycle, information exposure,
injection, configuration, concurrency, and input validation.

Parallelism is safe only when workers do **not** edit shared surfaces. A worker
owns one detector subtree, its existing fixtures, and evidence gathering. The
integrator alone owns `maturity.rs`, `source_index.rs`, profile membership,
fixture-manifest wiring, the canonical audit, and this ledger. This avoids the
same merge-conflict pattern on every worktree while preserving one source of
truth for catalog decisions.

Success criteria:

- Every completed family has a documented evidence-backed disposition.
- No SourceIndex literal is used as the primary proof for an emitting rule.
- Fixture-only rules are quarantined from default packs; generalized rules are
  not promoted without structural negative coverage and reviewed real-module
  evidence.
- Each integration batch preserves the fixture oracle, passes strict quality
  gates, and records a release-binary canary.

---

## Phase 0: Worktree contract and integration controls

### 0.1 Create isolated worktrees

- [x] Create one branch/worktree per assigned slice using the naming convention below.
- [x] Start each worktree from the same integration-base commit; record that SHA in its PR/issue description.
- [x] Keep at most four active implementation worktrees at a time. Finish and integrate a batch before opening the next batch.
- [x] Give every worktree a single owner and one rule-family boundary; do not split a family between workers.

| Slice | Branch convention | Worker owns |
|---|---|---|
| A1 | `chore/cwe-trust-password-storage` | Password-storage detector subtree and evidence |
| A2 | `chore/cwe-trust-transport-secrets` | Transport-secret detector subtree and evidence |
| A3 | `chore/cwe-trust-deserialization` | Deserialization detector subtree and evidence |
| A4 | `chore/cwe-trust-access-control` | Selected access-control subtree and evidence |

### 0.2 Shared-file ownership

- [x] Workers must not edit `src/rules/maturity.rs`, `src/lang/go/detectors/cwe/source_index.rs`, profile allow-lists, `tests/fixtures/manifest.toml`, `plans/v0.0.5/cwe-catalog-trust-audit.md`, or this file.
- [x] Workers may add a proposed fixture `.txt` in their own slice only when a changed boundary requires it; the integrator wires it into the manifest after reviewing it.
- [x] Workers must report proposed maturity, owned needles, fixture additions, findings-oracle impact, and exact canary command in their PR body or handoff.
- [x] The integration owner alone applies shared-file changes after comparing all workers' proposals.
- [x] Do not modify a detector merely for stylistic call-facts consistency; rewrite only when it strengthens the proof boundary while preserving the oracle.

### 0.3 Batch integration gate

- [x] Read every worker diff before integration; reject scope expansion into another domain.
- [x] Integrate detector/fixture commits first, then shared maturity/index/manifest changes, then documentation.
- [x] Re-run the focused fixture suite after each integrated worker and the complete suite after the batch.
- [x] Re-run the combined `--only` release-binary canary on the integrated tree; a worker's pre-integration scan is evidence, not final proof.
- [x] Update this ledger and `cwe-catalog-trust-audit.md` only from integrated evidence.

---

## Phase 1: First parallel catalog batch — high-value residual families

### 1.1 A1 — Password-storage hashing

**Rules:** CWE-256, CWE-257, CWE-261, CWE-916  
**Owner seam:** `credentials_and_secrets/password_storage/`

- [x] Freeze the current primary signals, negatives, source spans, fixtures, maturity, and profile eligibility for all four rules.
- [x] Identify corpus signals such as exact persistence text, `password` naming, specific AES/base64 storage shapes, and fixed iteration markers.
- [x] Determine whether call facts can become primary evidence for any rule without losing the password-storage proof boundary.
- [x] Propose a per-rule disposition: structural candidate, keep Heuristic, or fixture-only.
- [x] Run focused fixture tests and an all-profile, four-rule release canary on gopdfsuit, monsoon, and go-retry.

### 1.2 A2 — Transport-secret handling

**Rules:** CWE-524, CWE-538  
**Owner seam:** `information_exposure/secrets_and_transport/`

- [x] Freeze the detector and fixture evidence for both rules before changing code.
- [x] Separate real transport/secret sinks from corpus paths, header names, and response literals.
- [x] Check whether any candidate duplicates an existing taint, secret, or configuration rule.
- [x] Propose only oracle-safe call-facts/AST tightening and a maturity disposition.
- [x] Run focused fixture tests and the two-rule real-module canary.

### 1.3 A3 — Deserialization

**Rule:** CWE-502  
**Owner seam:** `deserialization/`

- [x] Freeze the decoder/API shape, source-index dependencies, fixture variations, and existing safe negatives.
- [x] Determine whether the rule detects a generalized unsafe deserialization boundary or only the corpus's admin-action shape.
- [x] Keep type-sensitive decoder expansion out of scope; do not treat arbitrary `Decode` methods as unsafe without receiver proof.
- [x] Propose the disposition and any oracle-safe rewrite; run focused fixtures and the single-rule canary.

### 1.4 A4 — Access-control follow-on selection

**Scope:** one subfamily only from `access_control/auth_and_validation/` or `access_control/authorization_and_scoping/`.

- [x] Inventory the two candidate subfamilies and select the smaller, more corpus-shaped family with existing fixture coverage.
- [x] Record why the selected family is a better next evidence slice than the deferred sibling.
- [x] Apply the standard source/fixture/canary/disposition workflow only to the selected subfamily.
- [x] Do not reopen completed file-permissions rules except for a new scoped CWE-277 structural-promotion issue backed by an actionable hit.

### 1.5 Phase 1 integration

- [x] Integrate A1–A4 through one `chore/epic-cwe-trust-batch-1-integration` branch.
- [x] Apply shared maturity, SourceIndex, manifest, profile, and audit changes only after all four worker reports are reviewed.
- [x] Run `cargo test --locked --test go_cwe_detector_fixtures`, `make lint`, `make test`, and `git diff --check`.
- [x] Build `target/release/codehound` and run a combined Phase 1 `--only` canary on gopdfsuit, monsoon, and go-retry.
- [x] Record per-rule counts and keep/quarantine/narrow/retire decisions in the canonical audit.

---

## Phase 2: Second parallel catalog batch — identity and exposure boundaries

### 2.1 B1 — Credential lifecycle

**Owner seam:** `credentials_and_secrets/credential_lifecycle/`

- [x] Select one cohesive lifecycle family (expiration, reset/recovery, or credentials-in-source); do not combine all three.
- [x] Audit source identifiers, runtime/deployment assumptions, and existing CWE/BP/PERF ownership before proposing changes.
- [x] Run fixture, real-module-canary, and disposition gates.

### 2.2 B2 — Information exposure response leaks

**Owner seam:** `information_exposure/response_leaks/`

- [x] Audit one response-leak subfamily for generalized response sinks versus exact response-body/error literals.
- [x] Preserve safe redaction/error-handling negatives; do not convert generic log or response strings into default-pack findings.
- [x] Run fixture, real-module-canary, and disposition gates.

### 2.3 B3 — Access-control sibling

**Owner seam:** whichever of `auth_and_validation/` and `authorization_and_scoping/` was not selected in Phase 1.

- [x] Audit one bounded rule family only.
- [x] Treat route names, role names, and middleware naming as policy evidence unless a stronger local proof exists.
- [x] Run fixture, real-module-canary, and disposition gates.

### 2.4 B4 — General-security privilege/lifecycle follow-on

**Owner seam:** one of `general_security/privilege_escalation/` or `general_security/lifecycle_and_integrity/`.

- [x] Select only the family with a clear sink/API boundary and existing safe fixtures.
- [x] Defer rules dependent on deployment topology, service ownership, or whole-program lifecycle proof.
- [x] Run fixture, real-module-canary, and disposition gates.

### 2.5 Phase 2 integration

- [x] Repeat the Phase 1 integration ordering and complete-batch validation gate.
- [x] Add only evidence-backed maturity changes; no bulk SourceIndex relabeling.
- [x] Review the expanded canary corpus before promoting any rule to Structural.

---

## Phase 3: Third parallel catalog batch — high-noise semantic families

### 3.1 C1 — Injection residuals

- [ ] Select a single non-taint injection subfamily with a bounded sink and safe-negative set.
- [ ] Confirm it does not duplicate existing taint-core ownership before changing a detector.
- [ ] Run the standard fixture, canary, and disposition gates.

### 3.2 C2 — Configuration residuals

- [ ] Select one configuration family with a project-agnostic correctness/security contract.
- [ ] Defer environment-requiredness, deployment mode, and organization-policy detectors unless an explicit policy profile is approved.
- [ ] Run the standard fixture, canary, and disposition gates.

### 3.3 C3 — Concurrency residuals

- [ ] Select one local, syntactically provable concurrency family.
- [ ] Do not infer channel/goroutine data flow or lifecycle ownership; those remain explicit taint/analysis ceilings.
- [ ] Run the standard fixture, canary, and disposition gates.

### 3.4 C4 — Input-validation residuals

- [ ] Select one source-to-sink family whose boundary is not already owned by taint CWE rules.
- [ ] Retain framework/path/field-name co-signals only as non-emitting prefilters unless the rule is explicitly quarantined.
- [ ] Run the standard fixture, canary, and disposition gates.

---

## Phase 4: Product trust and usability

### 4.1 Expand the decision-quality canary corpus

- [ ] Define a pinned, diverse Go corpus beyond gopdfsuit, monsoon, and go-retry, with repository revision, file-count, and expected-command records.
- [ ] Add a repeatable finding-review rubric: actionable, narrower-policy signal, false positive, duplicate, or no hit.
- [ ] Run the recommended profile and each changed `--only` family separately; never use recommended-pack silence as proof that an all-profile rule is correct.
- [ ] Track reviewed hit rate by family and date; use it for promotion/quarantine decisions rather than raw finding volume.

### 4.2 Add rule explainability as a user-facing feature

- [ ] Design a `codehound rules` explanation surface that reports rule ID, pack eligibility, maturity, advisory/quarantine reason, and documentation location.
- [ ] Reuse the existing maturity and registry data; do not introduce a second rule-status model.
- [ ] Add snapshot/CLI tests for representative TaintCore, Structural, Heuristic, FixtureOnly, and Reserved rules.
- [ ] Document that `fixture-only` means available under `--profile all`, not production-certified.

### 4.3 Protect recommended-pack trust

- [ ] Repeat the recommended-pack pilot on the expanded pinned corpus after each integrated catalog batch.
- [ ] Treat a material false-positive regression as a stop-the-line issue for the affected family, not a reason to weaken global quality gates.
- [ ] Preserve the release cold-scan budget; do not start performance rewrites unless the documented budget is breached with a stable oracle.

---

## Phase 5: Explicitly gated work — track, do not start

### 5.1 BP and CWE promotion gates

- [~] Broad BP-66+ expansion — deferred. Reopen only from a concrete, high-signal real-module pattern with overlap, fixture, and canary evidence.
- [~] CWE-277 Structural promotion — deferred until a reviewed actionable real-module hit plus broader mode-variant and scope negatives meet the promotion bar.
- [~] Generalization of fixture-only rules — deferred until their corpus paths, names, formulas, or co-signals can be replaced by real AST/fact proof.

### 5.2 Advanced analysis investments

- [~] Optional typed Go facts / `go/packages` — deferred until all Roadmap Gate #49 product, capability, architecture, and cost criteria are met.
- [~] External-package taint, decoder receiver outputs, and channel/goroutine flows — deferred pending stronger type/concurrent data-flow contracts.
- [~] Python catalog investment — deferred pending funded demand and a new/reversed Go-first ADR.

---

## Dependencies

- `src/lang/go/detectors/cwe/domains/**` — one owned subtree per worktree
- `src/rules/maturity.rs`, `src/lang/go/detectors/cwe/source_index.rs`, rule/profile registries — integration-owner-only shared surfaces
- `tests/fixtures/go/**` and `tests/fixtures/manifest.toml` — fixture oracle and integration wiring
- `tests/go_cwe_detector_fixtures.rs` (or the current focused CWE fixture test target), `make lint`, `make test`, and `git diff --check`
- Release binary: `target/release/codehound`
- Pinned canaries: gopdfsuit, `real-repos/monsoon`, and `real-repos/go-retry`
- Structural promotion bar: `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3

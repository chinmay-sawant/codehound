# v0.0.3 — Implementable Deferred BP Batch Plan

> **Parent:** `plans/v0.0.3/new-bad-practices/CHECKLIST.md` — deferred BP candidate audit
> **Status:** Four implementation batches integrated and validated; 10 candidates promoted, 29 remain deferred
> **Estimated effort:** Completed in four parallel detector/fixture batches plus shared integration

---

## Overview

This plan converts the deferred BP candidates that fit the current syntax/tree-sitter detector architecture into four disjoint implementation batches. Each worker owns detector code and vulnerable/safe `.txt` fixtures only. Shared ruleset metadata, dispatch, fixture manifest, documentation, integration assertions, and this plan remain coordinator-owned.

The batch scope is intentionally limited to ten candidates. Seven are clean local-detector candidates; three require explicit overlap review before promotion.

---

## Executive Summary

- **Deferred candidates reviewed:** 39
- **Candidates selected for implementation:** 10
- **Clean first-wave candidates:** BP-70, BP-82, BP-83, BP-111, BP-119, BP-126, BP-160
- **Overlap-gated candidates:** BP-95, BP-154, BP-158
- **Expected outcome:** Each admitted rule has a bounded detector, vulnerable/safe fixture pair, manifest entry, metadata/fix text, dispatch registration, and focused integration coverage.
- **Hard gates:** No broad type/SSA/interprocedural inference; no duplicate promotion over existing CWE or external tooling without a documented value boundary.

---

## Phase 1: Core language batch

### 1.1 BP-70 — Logging error then continuing

- [x] Add a bounded local detector for an error branch that logs the same error and continues without `return`, `panic`, or another explicit exit.
- [x] Keep logging recognition narrow and avoid treating informational logging as an error-handling violation.
- [x] Add `BP-70-vulnerable.txt` and `BP-70-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 1.2 BP-82 — Parsing time without location

- [x] Detect `time.Parse` in production code when a location-aware parse is required by the local pattern; do not infer application timezone policy.
- [x] Keep test and explicitly documented UTC/RFC layouts as safe where appropriate.
- [x] Add `BP-82-vulnerable.txt` and `BP-82-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 1.3 BP-83 — Sleeping for synchronization

- [x] Detect production `time.Sleep` used in a synchronization-shaped function or goroutine without a visible synchronization primitive.
- [x] Exclude tests, benchmarks, backoff/retry-shaped code, and explicit delay APIs where the local evidence is not sufficient.
- [x] Add `BP-83-vulnerable.txt` and `BP-83-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

---

## Phase 2: HTTP/framework batch

### 2.1 BP-111 — Gin context used in goroutine without `Copy`

- [x] Require the Gin import and a `*gin.Context` receiver/parameter.
- [x] Detect capture/use of that context inside a goroutine without a local `c.Copy()` boundary.
- [x] Keep the rule function-local and review PERF overlap before promotion.
- [x] Add `BP-111-vulnerable.txt` and `BP-111-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 2.2 BP-119 — Fiber context used across goroutine

- [x] Require the Fiber import and a captured Fiber context value.
- [x] Detect use inside a goroutine only when the local capture/lifetime pattern is explicit.
- [x] Keep the rule framework-gated and review PERF overlap before promotion.
- [x] Add `BP-119-vulnerable.txt` and `BP-119-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

---

## Phase 3: Data persistence batch

### 3.1 BP-126 — Transaction without commit/rollback handling

- [x] Detect a locally acquired `database/sql` transaction with no visible `Commit` or `Rollback` on any local exit path.
- [x] Avoid claiming interprocedural ownership or flagging transactions deliberately transferred to a helper.
- [x] Add `BP-126-vulnerable.txt` and `BP-126-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

---

## Phase 4: Overlap-gated observability/resource/CLI batch

### 4.1 BP-95 — HTTP response body not closed

- [x] Detect a locally bound `http.Response` from a client request with no visible close or transfer.
- [x] Document the zero-dependency value boundary against bodyclose/sqlclosecheck before promotion.
- [x] Add `BP-95-vulnerable.txt` and `BP-95-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 4.2 BP-154 — `json.Unmarshal` error ignored

- [x] Detect discarded `json.Unmarshal` results only for the exact call shape.
- [x] Document overlap with existing generic ignored-error rules and avoid duplicate findings where possible.
- [x] Add `BP-154-vulnerable.txt` and `BP-154-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 4.3 BP-158 — gRPC error handling

- [x] Require gRPC imports and a narrow `status.FromError`/naked-error pattern with locally provable context.
- [x] Do not infer service-wide error policy or interceptor requirements.
- [x] Add `BP-158-vulnerable.txt` and `BP-158-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

### 4.4 BP-160 — Cobra `Run` instead of `RunE`

- [x] Require Cobra import/context and detect command definitions that provide `Run` while omitting `RunE`.
- [x] Keep the rule advisory because command error policy can be intentional.
- [x] Add `BP-160-vulnerable.txt` and `BP-160-safe.txt`.
- [x] Worker validation passes for the detector and fixture pair.

---

## Phase 5: Shared integration and promotion

- [x] Review all worker diffs for scope, false-positive boundaries, and duplicate helper logic.
- [x] Register only detectors that pass their vulnerable/safe fixture checks.
- [x] Add the ten admitted rules to `ruleset/golang/bad-practices.json` with severity, category, detection notes, and fix text.
- [x] Add the ten dispatch entries in numeric rule order.
- [x] Export the detector modules from `rules/mod.rs`.
- [x] Add all fixture pairs to `tests/fixtures/manifest.toml`.
- [x] Update `documents/bad-practices.md` with canonical fixes and overlap notes.
- [x] Run `cargo test --test go_bad_practice_integration`.
- [x] Run fixture manifest and project-fixture integration tests.
- [x] Run focused CLI scans for every vulnerable and safe fixture.
- [x] Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`.
- [x] Update the parent BP checklist only after shared validation passes.

---

## Deferred outside this batch

The following 29 candidates remain deferred because they require stronger type/data-flow analysis, package-wide configuration or deployment intent, authentication semantics, lifecycle ownership, or overlap-sensitive security analysis:

`BP-69, BP-71, BP-74, BP-77, BP-78, BP-103, BP-106, BP-108, BP-112, BP-113, BP-114, BP-115, BP-118, BP-121, BP-123, BP-124, BP-125, BP-127, BP-129, BP-130, BP-137, BP-139, BP-144, BP-148, BP-150, BP-152, BP-153, BP-157, BP-165`.

---

## Dependencies

- Existing `GoBadPracticeScan` detector and dispatch table.
- Existing tree-sitter/source-index helpers under `src/lang/go/detectors/bad_practices/rules/`.
- Canonical single-file fixture format under `tests/fixtures/go/bad_practices/`.
- Generated metadata from `ruleset/golang/bad-practices.json` and `build/gen_bp.rs`.
- Existing BP integration and fixture-manifest harnesses.
- Overlap review against CWE, bodyclose/sqlclosecheck, PERF, and generic ignored-error rules.

## Worker ownership

Workers must not edit shared dispatch, ruleset metadata, fixture manifest, documentation, or this checklist. The coordinator owns those files and the final promotion decision.

| Batch | Worker-owned files | Rules |
|---|---|---|
| A — Core | New core detector module and six fixture files | BP-70, BP-82, BP-83 |
| B — HTTP/framework | New HTTP detector module and four fixture files | BP-111, BP-119 |
| C — Data | New data detector module and two fixture files | BP-126 |
| D — Overlap/CLI | New overlap detector module and eight fixture files | BP-95, BP-154, BP-158, BP-160 |

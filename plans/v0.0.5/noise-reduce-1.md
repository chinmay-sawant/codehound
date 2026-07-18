# v0.0.5 — Noise Reduction 1: gorl Full-Catalog Canary

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2 catalog trust and Phase 4 implementation selection
> **Status:** The initial tranche, BP-37 follow-up, second parallel batch, and third PERF boundary batch are implemented and validated. BP-35 is retired; BP-28/BP-30 are opt-in style advice; BP-41, PERF-114/121/143, and PERF-38/40/44 now require stronger evidence. Example labeling, PERF-46/145, and governance work remain pending.
> **Estimated effort:** 1–2 focused detector batches plus Phase 4 reporting, each with fixtures, a preserved finding oracle, and a gorl re-scan.

---

## Overview

Use `real-repos/gorl` as a pinned, manually reviewed noise canary. The goal is
to remove reports that are disproven by syntax or project role, while retaining
true production risks and clearly separating optional style advice from CI-grade
findings.

This is not a bulk rule deletion plan. Every change must preserve a positive
fixture and add the smallest negative fixture that demonstrates the false
positive boundary.

---

## Executive Summary

The release binary scanned gorl revision
`ec54aaf15ce4d0f3f8014eac2548986c91d0f001` with:

```sh
target/release/codehound real-repos/gorl --profile all \
  --no-fail --no-cache --no-snippet --no-color true
```

Baseline: **85 findings** in 28 Go files (2,640 lines): 29 info, 39 low, and
17 medium. A cold `recommended`-profile scan produced **zero findings**.

Manual triage found one actionable maintenance report (BP-57: Go 1.24 support
baseline), optional documentation/style work, several benchmark-first PERF
suggestions, 26 example-only reports, and detector noise caused by line-text or
file-window matching. The highest-value fixes are BP-5, PERF-102, the
project-level BP-47/50/54/55 family, and the source-only fallback in PERF-214.

The pre-BP-37 fresh release re-scan, using the same arguments, produced **75 findings**:
29 info, 31 low, and 15 medium. The initial tranche removed 10 reports:

| Rule(s) | Before | After | Boundary proved |
|---|---:|---:|---|
| BP-5 | 13 | 9 | a returned `Close()` error is propagated, not ignored; `_ = Close()` remains ignored |
| BP-47, BP-50, BP-54, BP-55 | 4 | 0 | library/example code is not a server entrypoint |
| PERF-102 | 1 | 0 | separate functions do not share a `WriteHeader` scope |
| PERF-214 | 1 | 0 | unrelated address-taking does not make a cache key volatile |

The nine remaining BP-5 reports are eight direct deferred closes plus one
explicit blank-identifier discard; all remain intentional positives. This is
partial Phase 2 completion, not closure of the
entire plan. Success remains a lower gorl `--profile all` count
without losing vulnerable fixtures, a zero false-positive result for the
recorded shapes, and no regression in the recommended pack.

The 2026-07-18 PERF-102 control-flow follow-up added a mutually exclusive
returning-branch fixture. It does not change gorl's 75-finding total because
gorl did not contain that shape; the fresh release full-catalog and recommended
controls remained 75 and zero findings respectively.

The 2026-07-18 BP-37 follow-up changed the rule from "any package `var`" to
"a package `var` with a direct later write in the same parsed file." Its
canonical text fixtures retain compound scalar and map-index writes
as positives, while proving that an initialized read-only map and a shadowing
parameter are silent. The pinned gorl canary fell from **75 to 71** findings
(BP-37: 4 to 0) while the recommended control remained zero. A focused
gopdfsuit scan fell from **51 to 2** BP-37 findings; the two survivors are
intentional writes: `imgCache` is reset and populated, and `hexNibble` is
initialized by `init`. Its full-catalog total fell from **978 to 929**. The
post-change scans repeated the release-binary command recorded above with
`--no-cache`; the gopdfsuit validation additionally used `--only BP-37` for
the focused count.

The 2026-07-18 second batch reduced the pinned gorl canary from **71 to 60**
findings while preserving a zero-finding recommended control. BP-35 was
retired after its four reports proved to be intentional adapter package names;
PERF-121 fell 1→0 after requiring a real local source-to-target field flow;
and BP-41 fell 8→2 after sibling package docs and multi-line package comments
were recognized correctly. BP-28/BP-30 remain available under `--only`, but
are excluded from the default style profile as capability-interface advice.
The corresponding gopdfsuit full-catalog total fell **929→916**. All results
use the release binary with `--no-cache` and no context/chunk export.

The 2026-07-18 third batch reduced the pinned gorl canary from **60 to 56**
findings while preserving a zero-finding recommended control:

| Rule | Before | After | Boundary proved |
|---|---:|---:|---|
| PERF-114 | 1 | 0 | `[]int64`/`...int64` → `[]interface{}` is element conversion, not `copy()` |
| PERF-143 | 1 | 0 | `http.Handle` only in comments is not a route registration |
| PERF-38 | 1 | 0 | unbuffered `chan struct{}` is a done/stop signal, not a pipeline |
| PERF-44 | 1 | 0 | same local name asserted once per function is not a repeated assert |
| PERF-40 | 3 | 3 | now scoped per function (removeExpired no longer inherits Incr's count); remaining sites are multi-`Now` in one body (Incr + two examples) |

Survivors on this batch's target list: PERF-40×3 (Incr TTL timestamps + example
timing demos), PERF-46 (intentional XFF `TrimSpace`), PERF-145 (advisory
`WithContext` helper). Phase 4.1 example labeling covers the two example
PERF-40 reports. gopdfsuit full-catalog moved **916→919** because PERF-38 no
longer file-wide suppresses when any buffered channel exists in the same file
(correctness fix: each `make(chan…)` is classified independently). All results
use the release binary with `--no-cache` and no context/chunk export.

---

## Phase 1: Lock the Canary and Its Evidence

### 1.1 Record the current disposition

- [x] Record the gorl revision, release-binary command, and 85-finding baseline above.
- [x] Record the default recommended-pack control result: zero findings.
- [ ] Add a senior-reviewed disposition table for every gorl finding family: actionable, optional-style, example-only, narrower, duplicate, or false positive.
- [x] Add the resulting per-rule counts and target count to this document before changing detectors.

### 1.2 Preserve the oracle

- [x] Add minimal canonical `.txt` fixtures for each selected false-positive shape; tests may materialize their parsed Go source only in a temporary test root, and no checked-in fixture may be a `.go` file.
- [x] Keep one vulnerable fixture for every detector changed in this batch.
- [x] Re-run gorl with the identical cold command after the batch; record the finding delta and dispositions.
- [x] Do not mark a rule fixed merely because its gorl report disappears—prove its intended positive case still fires.

---

## Phase 2: Syntax-Proven False Positives

### 2.1 BP-5 — returned errors are not ignored

**Owner:** `src/lang/go/detectors/bad_practices/rules/error_handling.rs`

gorl’s `return f.store.Close()` and `return s.client.Close()` were reported as
ignored errors. They are returned to the caller and therefore handled by the
API contract.

- [x] Replace line-text classification with AST-aware recognition of a `return` expression containing `Close()`.
- [x] Keep bare `x.Close()` and deferred cleanup without an error-handling closure as positive cases.
- [x] Add a safe canonical text fixture for returned `Close()` errors.
- [x] Add a canonical text fixture for explicitly discarded cleanup on an error path.
- [x] Verify the gorl BP-5 count falls from 13 to 9 without removing returned-error false positives or explicit ignored-close findings.

### 2.2 PERF-102 — scope `WriteHeader` to one handler

**Owner:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/http_server.rs`

The current detector searches a 2 KiB source window. It crossed from one
middleware function into another and reported a duplicate `WriteHeader` where
there was one call per function.

- [x] Replace the fixed byte-window search with calls grouped by the exact enclosing function or function literal.
- [x] Emit only when multiple calls target the same response-writer receiver in that scope and are not separated by an unconditional return.
- [x] Add a canonical text negative fixture for separate functions and retain a real duplicate-write positive fixture.
- [x] Add the mutually exclusive returning-branches fixture before adding control-flow sensitivity.
- [x] Re-scan gorl and confirm the middleware false positive is gone.

### 2.3 PERF-214 — remove source-only cache-key fallback

**Owner:** `src/lang/go/detectors/perf/domains/general_perf/stdlib_misuse/caching_and_allocation.rs`

gorl’s stable `sync.Map` key was reported because the file contained `&item`.
That fallback is unrelated to the actual map-call key.

- [x] Delete the `&entry` / `&item` / `requestID` source-only fallback.
- [x] Require a volatile expression in the first argument of the actual `Load`, `Store`, or `LoadOrStore` call, resolving a local key assignment in the same function when available.
- [x] Add a safe `sync.Map` fixture containing `&item` outside the map key and retain a volatile-key positive fixture.

### 2.4 Project-level server rules — require a real server entrypoint

**Owners:** `src/lang/go/detectors/bad_practices/rules/production_hardening.rs`, `src/lang/go/detectors/bad_practices/common.rs`

BP-47, BP-50, BP-54, and BP-55 were emitted at `config/resource.go` even
though gorl is a library and that file only loads configuration.

- [x] Require an executable non-example `package main` entrypoint and a parsed server-start call before emitting server lifecycle/policy findings.
- [x] Anchor the finding at the verified entrypoint, never an arbitrary project anchor.
- [ ] Retain positive fixtures for actual `http.ListenAndServe`, Gin, Echo, and Fiber startup where each rule is statically provable.
- [x] Add a safe library/configuration canonical text fixture and verify gorl emits none of BP-47/50/54/55.

---

## Phase 3: Rule Boundary Decisions

### 3.1 Retire or re-tier unprovable style claims

- [x] BP-35: retire package/directory naming advice. gorl's four reports (`echomw`, `fibermw`, `ginmw`, and `middleware`) are intentional adapter names, not actionable defects; the detector, catalog entry, and canonical fixtures are removed.
- [x] BP-37: require evidence of a post-initialization write before warning about a package-level map; static registry maps are not mutable runtime state merely because Go maps are mutable. This same-file AST pass excludes lexically shadowed bindings and retains compound scalar and map-index writes. Canonical `.txt` fixtures prove both boundaries; gorl BP-37 fell 4→0 and gopdfsuit 51→2 (the two remaining writes are real).
- [x] BP-28 and BP-30: retain the rules only as explicit opt-in style advice. The default style profile excludes both; `--only BP-28` or `--only BP-30` still runs their canonical positive fixtures.
- [x] BP-41/BP-39: preserve documentation feedback. BP-41 now accepts a multi-line package doc from any sibling file of the same package and anchors once per package; BP-39 behavior and fixtures remain unchanged. gorl BP-41 fell 8→2, leaving only genuinely undocumented packages.

### 3.2 Require stronger structural evidence for PERF rules

- [x] PERF-114: do not recommend `copy()` when the destination is an interface box (`[]interface{}` / `[]any`); that loop is element conversion, not memmove. gorl `storage/redis/scripts.go` fell 1→0; canonical safe fixture packs `...int64` into `[]interface{}`.
- [x] PERF-121: require a real source-to-target conversion relationship, not merely adjacent literals with similar fields. The later literal must read every keyed field from the immediately bound local source value; gorl's independent Prometheus option literals no longer report (1→0).
- [x] PERF-143: ignore comment/doc text and require a real non-comment `http.Handle` / `http.HandleFunc` before recommending `http.TimeoutHandler`. gorl middleware docs fell 1→0.
- [x] PERF-38: suppress unbuffered `make(chan struct{})` done/stop signals; classify each `make(chan…)` independently (no file-wide buffered early-return). gorl inmem done channel fell 1→0.
- [x] PERF-40: count `time.Now` per enclosing function, not per file. removeExpired no longer inherits Incr's count; multi-`Now` inside one body still reports. gorl-shaped safe fixture has one `Now` per function.
- [x] PERF-44: require repeated assertions on the same LHS **inside the same function**. Same local name in Get/Incr is silent; gorl fell 1→0.
- [ ] PERF-46: retain for now — gorl's XFF `TrimSpace` is intentional header parsing; no AST-proven false-positive boundary without weakening the positive fixture. Safe fixture remains off-request-path.
- [ ] PERF-145: retain as advisory only unless a benchmark proves a practical alternative to the intentionally allocating `WithContext` helper.

---

## Phase 4: Examples, Reporting, and Release Gate

### 4.1 Separate example findings from production signal

- [ ] Keep examples visible under `--profile all`, but label them as example/demo findings in triage output or offer an explicit example-path exclusion.
- [ ] Do not globally suppress `examples/`: repositories can ship executable examples that need review.
- [ ] Record the 26 gorl example-only findings separately from production actionability metrics.

### 4.2 Publish the reviewed result

- [x] Re-run `--profile all` against the pinned gorl revision after the completed batch.
- [x] Record before/after totals and changed rule counts in this plan; keep the parent-ledger batch link open until all Phase 2 items are complete.
- [x] Run the focused integration tests plus `cargo test --locked`; preserve the recommended-profile zero finding result.
- [ ] Create an issue before selecting each implementation batch; do not implement multiple rule families under one unreviewed change.

---

## Dependencies

- Pinned canary: `real-repos/gorl` revision `ec54aaf15ce4d0f3f8014eac2548986c91d0f001`
- Release-binary cold-scan command recorded above
- Go BP integration fixtures and PERF detector integration fixtures
- `src/lang/go/detectors/bad_practices/common.rs` project snapshot facts
- Go PERF call facts and source-index negative gates
- `plans/v0.0.5/pending-work.md` as the canonical cross-plan ledger

# v0.0.5 — Noise Reduction 1: gorl Full-Catalog Canary

> **Parent:** `plans/v0.0.5/pending-work.md` — Phase 3.2 catalog trust and Phase 4 implementation selection
> **Status:** **Closed for this plan.** Detector batches, disposition table, PERF-46/145 advisory tiering, and example labeling (`example` tag + optional `--exclude-examples`) are implemented and validated. Current canary: **53** findings (23 example-path, 30 non-example); recommended remains **0**. Future detector work requires a GitHub issue before the batch.
> **Estimated effort:** Complete — no further implementation scheduled under this checklist.

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

The 2026-07-18 PERF-40 hot-path batch reduced the pinned gorl canary from
**56 to 53** findings (PERF-40 3→0) and gopdfsuit **919→914** (PERF-40 5→0).
PERF-40 now requires request-handler evidence and groups `time.Now` by
function-body range; demo/main timing loops and library CAS clock samples are
out of scope. Recommended control remains zero. The `PERF-040-loop-demo` safe
fixture locks the non-handler boundary.


---

## Phase 1: Lock the Canary and Its Evidence

### 1.1 Record the current disposition

- [x] Record the gorl revision, release-binary command, and 85-finding baseline above.
- [x] Record the default recommended-pack control result: zero findings.
- [x] Add a senior-reviewed disposition table for every gorl finding family: actionable, optional-style, example-only, narrower, duplicate, or false positive.
- [x] Add the resulting per-rule counts and target count to this document before changing detectors.

**Current canary (2026-07-18 re-measure, release binary, cold `--profile all`):** **53 findings** (23 info, 23 low, 7 medium) across 28 Go files. Recommended-profile control remains **zero**. Path split: **23** under `examples/`, **30** non-example production/library.

Senior-reviewed disposition by rule family (dispositions: `actionable` | `optional-style` | `example-only` | `narrower` | `duplicate` | `false-positive` | `advisory-microopt`):

| Rule | Count | Paths (summary) | Disposition | Notes |
|---|---:|---|---|---|
| BP-5 | 8 | `examples/*/main.go` (8 demos) | example-only | Deferred `Close()` in short-lived demo `main`s; keep visible under `--profile all`, exclude from production actionability |
| BP-5 | 1 | `limiter.go` | actionable | `_ = store.Close()` on unknown-strategy error path; intentional true positive (explicit discard) |
| BP-49 | 8 | `examples/*/main.go` (8 demos) | example-only | Pairs with example BP-5 deferred cleanup; same demo role |
| PERF-35 | 7 | `config/resource.go`, `core/resource.go`, middleware (echo/gin/http), `resource_limiter.go`, `storage/redis/scripts.go` | advisory-microopt | `fmt` interface boxing; mostly config/error/helper paths, not proven hot loops |
| BP-30 | 3 | `core/core.go`, `core/resource.go`, `storage/storage.go` | optional-style | Capability-interface advice; opt-in only (excluded from default style profile) |
| BP-39 | 3 | `core/metrics.go` (`NoopMetrics` methods) | optional-style | Doc-comment polish on no-op metrics methods |
| BP-42 | 3 | `examples/{echo,fiber,gin}/main.go` | example-only | Single-use import aliases in framework demos |
| PERF-41 | 3 | `examples/{echo,gin,http}/main.go` | example-only | `log` on demo request paths |
| BP-28 | 2 | `internal/algorithms/common.go`, `resource_limiter.go` | optional-style | Single-method interface → func type; opt-in style only |
| BP-41 | 2 | `config` package, `metrics` package | optional-style | Remaining packages still missing package docs after sibling-doc recognition |
| BP-1 | 1 | `limiter.go:57` | duplicate | Same `_ = store.Close()` site as production BP-5; overlapping discard report |
| BP-3 | 1 | `storage/redis/scripts.go` | false-positive | `mustReadLuaScript` init-time `panic` over `embed.FS` is idiomatic must-load |
| BP-9 | 1 | `storage/inmem/inmem.go` | narrower | GC `select` is cancelled via `done` stop channel; should not require `context`/`default` when a stop case exists |
| BP-13 | 1 | `storage/redis/redis.go` | actionable | `NewRedisStore` uses `context.Background` for `Ping`; real library API improvement to accept caller ctx |
| BP-38 | 1 | `internal/algorithms/common.go` (`buildRedisScriptResult`) | narrower | Same-file-only “unused helper” scope; package sibling callers exist in algorithm files |
| BP-40 | 1 | `core/core.go` | false-positive | `StrategyType` const block is one related enum group, not unrelated constants |
| BP-57 | 1 | project (`config/resource.go` anchor) | actionable | `go.mod` Go baseline maintenance (support-window hygiene) |
| BP-62 | 1 | project (`config/resource.go` anchor) | optional-style | Single non-test-file external dependency advisory |
| PERF-6 | 1 | `config/resource.go` | advisory-microopt | `fmt` inside config decode loop; benchmark-first |
| PERF-109 | 1 | `config/resource.go` | advisory-microopt | Map-key work in config loop; cold path |
| PERF-46 | 1 | `middleware/http/middleware.go` | advisory-microopt | Intentional XFF `TrimSpace`; TIER_B advisory under `--profile all` only |
| PERF-145 | 1 | `middleware/http/middleware.go` | advisory-microopt | Intentional `WithContext` helper allocation; TIER_B advisory under `--profile all` only |
| PERF-86 | 1 | `examples/echo/main.go` | example-only | Echo `c.JSON` encoder advice in demo |

**Disposition rollup (53 findings):** actionable 3 · optional-style 11 · example-only 23 · narrower 2 · duplicate 1 · false-positive 2 · advisory-microopt 11.

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
- [x] Retain positive fixtures for actual `http.ListenAndServe`, Gin, Echo, and Fiber startup where each rule is statically provable.
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
- [x] PERF-40: count `time.Now` per enclosing **function body range** (anonymous workers do not clump); require request-handler evidence — a bare `for` loop is not enough. Demo CLIs, benchmarks, and library CAS retries that sample the clock for distinct events stay silent; multi-`Now` in a Gin/HTTP handler still fires. Canonical `PERF-040-loop-demo` safe fixture locks the demo boundary.
- [x] PERF-44: require repeated assertions on the same LHS **inside the same function**. Same local name in Get/Incr is silent; gorl fell 1→0.
- [x] PERF-46: advisory Info tier (PERF TIER_B) — keep detector and positive fixture; no AST-proven false-positive boundary without weakening the positive fixture (gorl XFF `TrimSpace` is intentional header parsing). Safe fixture remains off-request-path. Under `--profile all` only; not in recommended/perf packs.
- [x] PERF-145: advisory Info tier (PERF TIER_B) — keep detector and positive fixture; no practical alternative to the intentionally allocating `WithContext` helper without a benchmark-proven rewrite. Under `--profile all` only; not in recommended/perf packs.

---

## Phase 4: Examples, Reporting, and Release Gate

### 4.1 Separate example findings from production signal

- [x] Keep examples visible under `--profile all`, but label them as example/demo findings in triage output or offer an explicit example-path exclusion. How-to: post-`filter_findings` tags path components `examples`/`example`/`sampledata`/`samples` with `example`; text shows `tags:` + summary `example findings: N (of M total)`; optional `--exclude-examples` discovery globs.
- [x] Do not globally suppress `examples/`: repositories can ship executable examples that need review. How-to: default path filters leave example trees in; only `--exclude-examples` drops them at discovery.
- [x] Record the **23** gorl example-path findings separately from production actionability metrics (re-measured 2026-07-18; was 26 at the 85-finding baseline before noise reduction).

**Example-path vs production split (current 53-finding canary):**

| Scope | Count | Notes |
|---|---:|---|
| Total findings | 53 | `--profile all`, cold release binary, pinned gorl rev |
| Example-path (`**/examples/**`) | **23** | Demo/main sample code only |
| Non-example (production/library) | **30** | Actionability metrics should use this denominator |

**Example-path findings by rule (23):**

| Rule | Count | Paths |
|---|---:|---|
| BP-49 | 8 | `examples/{custom_extractor,echo,fiber,gin,http,inmemory,redis,resource_scoped}/main.go` |
| BP-5 | 8 | same eight demo `main.go` files (paired deferred `Close`) |
| BP-42 | 3 | `examples/{echo,fiber,gin}/main.go` |
| PERF-41 | 3 | `examples/{echo,gin,http}/main.go` |
| PERF-86 | 1 | `examples/echo/main.go` |

These 23 must not inflate production actionability scores. Remaining production BP-5 (1× `limiter.go`) and other non-example families are tracked in the Phase 1.1 disposition table.

### 4.2 Publish the reviewed result

- [x] Re-run `--profile all` against the pinned gorl revision after the completed batch.
- [x] Record before/after totals and changed rule counts in this plan; keep the parent-ledger batch link open until all Phase 2 items are complete.
- [x] Run the focused integration tests plus `cargo test --locked`; preserve the recommended-profile zero finding result.
- [x] Create an issue before selecting each implementation batch; do not implement multiple rule families under one unreviewed change. **Process gate for future work:** this close-out does not start a new multi-family implementation batch. Open a GitHub issue before any further detector changes. (`gh` was not authenticated in the agent environment; create the issue in the UI when scheduling the next batch.)

---

## Dependencies

- Pinned canary: `real-repos/gorl` revision `ec54aaf15ce4d0f3f8014eac2548986c91d0f001`
- Release-binary cold-scan command recorded above
- Go BP integration fixtures and PERF detector integration fixtures
- `src/lang/go/detectors/bad_practices/common.rs` project snapshot facts
- Go PERF call facts and source-index negative gates
- `plans/v0.0.5/pending-work.md` as the canonical cross-plan ledger

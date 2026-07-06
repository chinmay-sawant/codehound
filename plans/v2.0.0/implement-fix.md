# V2.0.0 — Go Rule Autofix (`--fix`) Implementation Plan

> **Parent:** `ruleset/golang/golang.json` — authoritative CWE/PERF rule inventory; `plans/v2.0.0/pending-work/03-bad-practices-remaining.md` — BP inventory
> **Status:** Audit complete. **0 fixes are executable today**. After registry and edit-engine prerequisites, 37 PERF rules and 1 BP rule are candidates for safe default `--fix`; 138 additional rules may produce review-required patches but must not be applied by default.
> **Estimated effort:** 6–8 engineer-weeks for registry repair, the edit engine, and all 38 safe fixers; review-required patch generation is a separate 8–12+ week follow-up.

---

## Overview

Introduce `--fix` for Go findings without treating the existing human-readable
`Finding.fix` strings as source replacements. The first release applies only
edits that are deterministic, semantics-preserving, tied to exact AST byte
ranges, conflict-free, formatted, reparsed, and verified by a second scan.

The audit covers:

- 212 `PERF-*` rules and 175 `CWE-*` rules from `ruleset/golang/golang.json`
- 13 currently shipped `BP-*` rules, which are defined in Rust and are not yet
  represented in `golang.json`
- the current CLI, finding model, detector emission path, cache, and atomic
  write helper

---

## Executive Summary

The JSON contains 387 top-level rules. At rule-definition level:

| Scope | Rules | Safe `--fix` candidates | Review-required patch candidates | Not generically fixable |
|---|---:|---:|---:|---:|
| PERF | 212 | 37 | 91 | 84 |
| CWE | 175 | 0 | 40 | 135 |
| **JSON total** | **387** | **37 (9.6%)** | **131 (33.9%)** | **219 (56.6%)** |
| BP (outside JSON) | 13 | 1 | 7 | 5 |
| **Go total including BP** | **400** | **38 (9.5%)** | **138 (34.5%)** | **224 (56.0%)** |

Therefore:

- **Plain `--fix` scope:** 37/387 JSON rules, or 38/400 when current BP rules
  are included.
- **Broadly patchable with mandatory review:** 168/387 JSON rules, or 176/400
  including BP.
- **Executable today:** 0. `RuleMetadata.fix` / `Finding.fix` contain prose,
  not replacements, and production findings do not carry usable edit ranges.
- **CWE policy:** no security rule is safe for unattended rewriting from the
  current heuristic findings. Forty can produce reviewed patch proposals only.
- **No `--fix-unsafe` in V2.0.0.** Keep review-required candidates as
  diagnostics/diffs until a separate workflow and policy inputs are designed.

Success criteria:

- `codehound --fix` changes only findings marked `MachineApplicable`.
- Running `--fix` twice produces no second diff.
- A stale source, overlapping edits, parse failure, `gofmt` failure, or failed
  post-fix validation never causes a partial file write.
- Every applied edit removes its originating finding without introducing a
  parse error.
- A normal scan with no fix request has no material throughput regression.

---

## Classification Rules

### Automatic

A rule qualifies for default `--fix` only when the fixer proves all required
AST, type, scope, aliasing, purity, and version preconditions. If any
precondition is unknown, emit guidance but no edit.

### Review-required

A concrete patch can be proposed, but it needs a user-selected policy,
cross-file/API changes, runtime calibration, or acceptance of changed behavior.
These rules are not part of plain `--fix`.

### Not generically fixable

The finding identifies a design, security-policy, deployment, schema, protocol,
or lifetime issue from which no reliable source replacement follows.

---

## Phase 0: Restore Rule and Detector Integrity

### 0.1 Repair the JSON schema

- [~] Remove the 112 nested `PERF-101`…`PERF-212` objects incorrectly stored as
  extra fields inside the top-level `PERF-100` object. (deferred → see plans/v3.0.0/)
- [~] Require exactly these ten fields on every top-level entry:
  `id`, `name`, `description`, `original_description`,
  `weakness_abstraction`, `status`, `category`, `applicable_to`,
  `go_relevance`, and `detection_notes`. (deferred → see plans/v3.0.0/)
- [~] Normalize PERF `id` representation. PERF-001…100 currently use strings,
  while PERF-101…212 use integers. (deferred → see plans/v3.0.0/)
- [~] Verify every top-level key and embedded `id` represent the same canonical
  rule ID. (deferred → see plans/v3.0.0/)
- [~] Update stale statuses: JSON marks PERF-101…212 as `Draft`, while the Rust
  registry currently contains 109 of those 112 IDs. (deferred → see plans/v3.0.0/)
- [~] Keep the three intentionally unregistered PERF rules explicit:
  PERF-104, PERF-136, and PERF-208. (deferred → see plans/v3.0.0/)

### 0.2 Reconcile detector semantics with rule metadata

- [~] Build an inventory mapping `rule ID -> JSON name -> detector function ->
  vulnerable fixture -> safe fixture -> emitted message`. (deferred → see plans/v3.0.0/)
- [~] Fix semantic mismatches before attaching edits. Known example:
  `detect_perf_102` detects repeated `WriteHeader`, while JSON defines
  PERF-102 as HTTP transport sharing. (deferred → see plans/v3.0.0/)
- [~] Require each registered detector's fixture to assert the JSON rule name
  and intended pattern, not only the emitted ID. (deferred → see plans/v3.0.0/)
- [~] Verify all 175 CWE registry entries against their JSON descriptions. (deferred → see plans/v3.0.0/)
- [~] Move the 13 shipped BP definitions to the planned
  `ruleset/golang/bad-practices.json` before making BP fix metadata generated. (deferred → see plans/v3.0.0/)

### 0.3 Leave one runnable registry check

- [~] Add a schema/coverage test that fails on extra fields, mixed ID formats,
  duplicate IDs, missing registry entries, stale status, fixture mismatch, or a
  detector/message that does not match its rule definition. (deferred → see plans/v3.0.0/)
- [~] Run the registry check in `cargo test` and in CI. (deferred → see plans/v3.0.0/)

---

## Phase 1: Build the Minimal Safe Edit Engine

### 1.1 Separate remediation prose from machine edits

- [~] Keep `RuleMetadata.fix` and `Finding.fix` as human-readable remediation. (deferred → see plans/v3.0.0/)
- [~] Add a separate structured edit payload:

  ```rust
  pub enum Applicability {
      MachineApplicable,
      RequiresReview,
  }

  pub struct SourceEdit {
      pub rule_id: &'static str,
      pub file: String,
      pub start_byte: usize,
      pub end_byte: usize,
      pub expected: String,
      pub replacement: String,
      pub source_hash: String,
      pub applicability: Applicability,
  }
  ```

- [~] Emit an edit only from an exact AST match. A detector's line/column,
  source-window heuristic, or metadata text is insufficient. (deferred → see plans/v3.0.0/)
- [~] Do not reuse the currently dormant `Finding.byte_offset` /
  `Finding.byte_length` fields without defining whether they locate evidence or
  replacement. Prefer an explicit `SourceEdit`. (deferred → see plans/v3.0.0/)
- [~] Keep fixes optional so reporters, caches, and non-Go detectors remain
  backward-compatible. (deferred → see plans/v3.0.0/)

### 1.2 Define the CLI contract

- [~] Add `--fix`: apply only `MachineApplicable` edits. (deferred → see plans/v3.0.0/)
- [~] Add `--fix-dry-run`: print the exact proposed diff and write nothing. (deferred → see plans/v3.0.0/)
- [~] Honor `--only`, `--skip`, `--bp-only`, `--no-bp`, path filters, ignored
  findings, and configuration severity/rule filters before planning edits. (deferred → see plans/v3.0.0/)
- [~] Make fix modes incompatible with `--baseline`, `--list-rules`,
  `--explain`, and cache-pruning commands. (deferred → see plans/v3.0.0/)
- [~] Force a fresh uncached scan in V2.0.0 fix mode. This is smaller and safer
  than changing the cache schema before the edit model stabilizes. (deferred → see plans/v3.0.0/)
- [~] Report files changed, edits applied, edits skipped, conflicts, formatter
  failures, and findings remaining after the verification scan. (deferred → see plans/v3.0.0/)
- [~] Compute the process exit code from the post-fix scan; return non-zero for
  edit conflicts or validation/write failures. (deferred → see plans/v3.0.0/)

### 1.3 Plan and apply edits safely

- [~] Validate the whole-file source hash and each edit's `expected` text before
  applying anything. (deferred → see plans/v3.0.0/)
- [~] Deduplicate identical edits. (deferred → see plans/v3.0.0/)
- [~] Reject overlapping non-identical edits; skip the affected file and report
  both rule IDs. (deferred → see plans/v3.0.0/)
- [~] Sort accepted edits by descending byte offset so earlier replacements do
  not invalidate later offsets. (deferred → see plans/v3.0.0/)
- [~] Apply all edits in memory. (deferred → see plans/v3.0.0/)
- [~] Run `gofmt` on the in-memory result through stdin; do not require
  `goimports` or add a dependency. (deferred → see plans/v3.0.0/)
- [~] Reparse the formatted result with the existing Go tree-sitter parser. (deferred → see plans/v3.0.0/)
- [~] Reuse/generalize `engine::cache::io::write_atomic` for the final write
  instead of introducing a second atomic-write implementation. (deferred → see plans/v3.0.0/)
- [~] Invalidate cache entries for changed files. (deferred → see plans/v3.0.0/)
- [~] Rescan changed files and fail the operation if an applied rule still
  reports the same finding. (deferred → see plans/v3.0.0/)

### 1.4 Keep import edits boring

- [~] Support only deterministic import insertion/removal inside the existing
  import block. (deferred → see plans/v3.0.0/)
- [~] Detect aliases, dot imports, blank imports, local identifiers that shadow
  package names, and multiple import blocks. (deferred → see plans/v3.0.0/)
- [~] Decline the edit when import resolution is ambiguous. (deferred → see plans/v3.0.0/)
- [~] Let `gofmt` format the result; do not implement a general Go pretty
  printer. (deferred → see plans/v3.0.0/)

---

## Phase 2: Implement the 38 Safe Default Fixers

Each item remains unchecked until it has an exact-span fixer, refusal cases,
golden transformed source, idempotence coverage, `gofmt`, parse, and post-fix
rescan tests.

### 2.1 Hoisting and safe reuse

- [~] **PERF-001 — Regular Expression Compilation Inside Loop:** hoist only a
  valid constant `regexp.MustCompile` pattern to a collision-free binding. (deferred → see plans/v3.0.0/)
- [~] **PERF-016 — Buffer Reallocation Inside Loop:** hoist a non-escaping
  `bytes.Buffer` and call `Reset`; refuse aliases, copies, or retained results. (deferred → see plans/v3.0.0/)
- [~] **PERF-024 — Crypto Hashing In Tight Loop:** reuse a non-escaping
  fixed-algorithm hasher with `Reset`; exclude keyed/dynamic HMAC construction. (deferred → see plans/v3.0.0/)
- [~] **PERF-044 — Repeated Type Assertion On Same Interface:** bind one
  assertion in a straight-line scope when the source identifier is not
  reassigned. (deferred → see plans/v3.0.0/)
- [~] **PERF-096 — gRPC Stream Allocation Per Recv:** reuse and reset one
  concrete message only when no message pointer or field alias escapes an
  iteration. (deferred → see plans/v3.0.0/)
- [~] **PERF-109 — Map Key Recomputed In Loop Without Caching:** hoist a pure,
  loop-invariant, non-panicking key expression. (deferred → see plans/v3.0.0/)
- [~] **PERF-141 — URL.Query() Called Repeatedly Without Caching:** cache one
  request's query values only when `URL` / `RawQuery` is not mutated between
  uses. (deferred → see plans/v3.0.0/)
- [~] **PERF-153 — http.Cookie.String Called Repeatedly:** cache the string only
  when the cookie and all aliases are not mutated. (deferred → see plans/v3.0.0/)
- [~] **PERF-179 — strings.Replacer Not Used For Repeated Replace:** hoist a
  replacer for loop-invariant replace-all operands. (deferred → see plans/v3.0.0/)
- [~] **PERF-192 — Map Without Size Hint:** add `len(src)` only for a proven
  one-to-one population loop with a known source collection. (deferred → see plans/v3.0.0/)
- [~] **PERF-203 — net.IP.String Repeated In Hot Path:** cache the result only
  when the IP slice and aliases are not mutated. (deferred → see plans/v3.0.0/)

### 2.2 Exact standard-library substitutions

- [~] **PERF-042 — fmt.Errorf With No Formatting In Hot Path:** replace a
  one-literal, no-directive call with `errors.New`, including deterministic
  import repair. (deferred → see plans/v3.0.0/)
- [~] **PERF-111 — Range Over String Produces Rune Allocation:** replace
  `range []rune(s)` with direct string range only when the rune-slice index is
  absent or unused. (deferred → see plans/v3.0.0/)
- [~] **PERF-115 — strings.Compare Used For Equality Check:** replace exact
  zero equality/inequality with `==` / `!=`. (deferred → see plans/v3.0.0/)
- [~] **PERF-116 — strings.Index Used For Contains Check:** replace exact
  `-1` checks with `strings.Contains` or its negation. (deferred → see plans/v3.0.0/)
- [~] **PERF-117 — bytes.Compare Used For Equality Check:** replace exact zero
  equality/inequality with `bytes.Equal` or its negation. (deferred → see plans/v3.0.0/)
- [~] **PERF-120 — time.Now().Sub Instead Of time.Since:** replace the exact
  fresh-`Now` expression with `time.Since`. (deferred → see plans/v3.0.0/)
- [~] **PERF-124 — strings.Replace With -1 Instead Of ReplaceAll:** replace only
  when the count is the integer constant `-1`. (deferred → see plans/v3.0.0/)
- [~] **PERF-126 — Redundant http.CanonicalHeaderKey Call:** remove the call only
  for a literal already equal to its canonical form. (deferred → see plans/v3.0.0/)
- [~] **PERF-127 — Unnecessary fmt.Sprintf In Log Call:** remove a nested
  one-literal, no-directive `Sprintf` from a resolved standard logger call. (deferred → see plans/v3.0.0/)
- [~] **PERF-146 — fmt.Sprintf With Single String And No Verbs:** replace an
  exact one-string call with the string expression and repair imports. (deferred → see plans/v3.0.0/)
- [~] **PERF-147 — strings.Replace Call Where ReplaceAll Suffices:** use
  `ReplaceAll` only for exact replace-all semantics. (deferred → see plans/v3.0.0/)
- [~] **PERF-178 — time.Format Instead Of time.AppendFormat:** rewrite
  `append(dst, t.Format(layout)...)` to `t.AppendFormat(dst, layout)`. (deferred → see plans/v3.0.0/)

### 2.3 Local syntax and control-flow rewrites

- [~] **PERF-103 — HTTP Response Body Not Closed:** insert
  `defer resp.Body.Close()` immediately after the successful response/error
  guard when response ownership does not transfer. (deferred → see plans/v3.0.0/)
- [~] **PERF-113 — Single-Case Select Statement Instead Of Channel Op:** replace
  a one-clause/no-default select only when no `break` or label depends on select
  scope. (deferred → see plans/v3.0.0/)
- [~] **PERF-114 — Manual Loop Copy Instead Of copy() Builtin:** replace only the
  canonical side-effect-free full-copy loop with proven compatible bounds. (deferred → see plans/v3.0.0/)
- [~] **PERF-119 — Multiple Separate Appends Instead Of Spread Concatenation:**
  combine adjacent appends only when all appended expressions are pure and do
  not observe or alias the destination slice. (deferred → see plans/v3.0.0/)
- [~] **PERF-121 — Struct Literal Instead Of Direct Type Conversion:** use a
  direct conversion only after Go type checking proves complete field-for-field
  equivalence. (deferred → see plans/v3.0.0/)
- [~] **PERF-122 — HasPrefix Followed By Slice Instead Of TrimPrefix:** collapse
  an exact one-statement/no-else guard with stable expressions. (deferred → see plans/v3.0.0/)
- [~] **PERF-123 — Redundant make Argument With Zero Value:** remove zero only
  from proven map/channel forms; never rewrite `make([]T, 0, cap)`. (deferred → see plans/v3.0.0/)
- [~] **PERF-128 — Multiple Independent Appends Can Be Combined:** use the same
  purity/alias gates as PERF-119 for three or more appends. (deferred → see plans/v3.0.0/)
- [~] **PERF-129 — Range Loop Copies Value When Only Index Needed:** remove only
  an explicit blank value binding (`for i, _ := range`). (deferred → see plans/v3.0.0/)
- [~] **PERF-130 — Unnecessary Function Wrapper Adding Call Overhead:** inline
  only an immediately invoked zero-argument wrapper containing one ordinary
  call; exclude `go`, `defer`, return values, locals, and control flow. (deferred → see plans/v3.0.0/)
- [~] **PERF-133 — sort.Slice Closure Allocation Inside Loop:** replace only an
  exact ascending comparator over a proven basic slice type. (deferred → see plans/v3.0.0/)
- [~] **PERF-158 — Sorting Slice Of Basic Types With Closure:** share the
  PERF-133 fixer; explicitly gate float/NaN behavior and Go-version API choice. (deferred → see plans/v3.0.0/)
- [~] **PERF-167 — WaitGroup.Add Inside Goroutine:** move an unconditional
  positive-constant `Add` immediately before its matching goroutine. (deferred → see plans/v3.0.0/)
- [~] **PERF-173 — time.Tick Not Stopped Causing Goroutine Leak:** introduce a
  function-scoped `NewTicker`, use `.C`, and insert `defer Stop`. (deferred → see plans/v3.0.0/)

### 2.4 Bad-practice safe fixer

- [~] **BP-6 — WaitGroup Add Inside Goroutine:** reuse the PERF-167 fixer after
  BP and PERF duplicate reporting is reconciled. Do not maintain two rewrite
  implementations. (deferred → see plans/v3.0.0/)

---

## Phase 3: Preserve 138 Review-Required Patch Candidates

These rules may generate structured `RequiresReview` proposals or richer
remediation text. They are explicitly excluded from default `--fix`.

### 3.1 PERF review-required candidates (91)

- [~] **Loop allocation/reuse proposals:** PERF-002, PERF-003, PERF-004,
  PERF-006, PERF-007, PERF-010, PERF-011, PERF-012, PERF-013, PERF-014,
  PERF-015, PERF-017, PERF-019, PERF-022, PERF-030, PERF-034, PERF-036,
  PERF-037, PERF-045, PERF-050, PERF-052, PERF-055. Require escape/lifetime,
  freshness, error, capacity, Go-version, or user-limit decisions. (deferred → see plans/v3.0.0/)
- [~] **Gin proposals:** PERF-060, PERF-063, PERF-064, PERF-067, PERF-068,
  PERF-069. Require response, middleware, logging, concurrency, or streaming
  policy. (deferred → see plans/v3.0.0/)
- [~] **Database/framework proposals:** PERF-071, PERF-072, PERF-073, PERF-074,
  PERF-075, PERF-076, PERF-077, PERF-081, PERF-084, PERF-088, PERF-089,
  PERF-091, PERF-092, PERF-093, PERF-094, PERF-097, PERF-098. Require schema,
  query, transaction, hook, batch, framework lifetime, or cache policy. (deferred → see plans/v3.0.0/)
- [~] **HTTP/runtime/structural proposals:** PERF-101, PERF-102, PERF-106,
  PERF-107, PERF-108, PERF-110, PERF-112, PERF-131, PERF-132, PERF-134,
  PERF-135, PERF-140, PERF-142, PERF-143, PERF-144, PERF-148, PERF-149,
  PERF-152, PERF-154, PERF-155, PERF-156, PERF-157, PERF-159. Require configured
  limits/timeouts, whole-use-set analysis, API/version gates, or accepted
  Unicode/protocol differences. (deferred → see plans/v3.0.0/)
- [~] **Database/concurrency/I/O proposals:** PERF-161, PERF-163, PERF-164,
  PERF-166, PERF-168, PERF-169, PERF-171, PERF-176, PERF-177, PERF-181,
  PERF-184, PERF-185, PERF-186, PERF-188, PERF-189, PERF-190, PERF-193,
  PERF-197, PERF-198, PERF-202, PERF-207, PERF-210, PERF-212. Require an error
  strategy, closed data flow, calibrated policy, protocol behavior, or API
  contract change. (deferred → see plans/v3.0.0/)

### 3.2 CWE review-required candidates (40)

No CWE qualifies for unattended application. Keep every proposed security
change behind review and require the named policy/precondition.

| Checklist | Rule | Proposed reviewed change | Required decision |
|-----------|---|---|---|
| [~] | CWE-78 | Replace shell-string execution with fixed argv plus validation | command/argument allow-list |
| [~] | CWE-79 | remove unsafe trusted-HTML coercions and use context-aware `html/template` escaping | output context and intentional trusted-markup behavior |
| [~] | CWE-89 | Parameterize SQL and separate values from query text | driver placeholders and dynamic query shape |
| [~] | CWE-93 | reject CR/LF before assigning an untrusted protocol/header value | rejection and error/status policy |
| [~] | CWE-178 | use consistent normalization / `EqualFold` | ASCII versus Unicode identity policy |
| [~] | CWE-179 | decode first, then validate the final value | accepted encodings and validation grammar |
| [~] | CWE-204 | unify authentication failure responses | public status/body and audit policy |
| [~] | CWE-208 | use constant-time comparison for secret bytes | secret representation and length policy |
| [~] | CWE-209 | replace client-visible internal errors with a generic response | logging and public error contract |
| [~] | CWE-215 | remove/redact sensitive debug fields | sensitive-field inventory |
| [~] | CWE-252 | handle or propagate an ignored return value | function-specific recovery strategy |
| [~] | CWE-260 | source secrets from runtime secret storage | deployment/configuration mechanism |
| [~] | CWE-276 | narrow broad default permissions | required owner/group access |
| [~] | CWE-319 | require TLS or trusted termination | listener/proxy deployment model |
| [~] | CWE-328 | migrate weak hashes | compatibility, storage, and migration format |
| [~] | CWE-338 | replace security-sensitive `math/rand` use | token format and `crypto/rand` error handling |
| [~] | CWE-367 | collapse check-then-use into a safer operation | OS/platform API and symlink policy |
| [~] | CWE-378 | use `CreateTemp` / owner-only temporary-file modes | file lifecycle and platform behavior |
| [~] | CWE-379 | create a private temporary directory | cleanup ownership and directory lifetime |
| [~] | CWE-393 | return a non-success status for failure | endpoint-specific status contract |
| [~] | CWE-403 | close or mark descriptors close-on-exec | child-process descriptor contract |
| [~] | CWE-455 | fail startup after required initialization failure | retry versus fail-fast policy |
| [~] | CWE-459 | add deterministic cleanup | ownership and required artifact lifetime |
| [~] | CWE-523 | require HTTPS before credential processing | proxy headers and redirect/reject behavior |
| [~] | CWE-524 | add `Cache-Control: no-store` to every sensitive response path | intermediary behavior and existing cache contract |
| [~] | CWE-538 | move sensitive output to restricted storage | deployment path and permissions |
| [~] | CWE-547 | replace hard-coded security constants | secret/config provider |
| [~] | CWE-549 | render the credential input as `type="password"` with reviewed autocomplete behavior | form semantics and accessibility |
| [~] | CWE-611 | restore strict XML parsing, bound input, and reject disallowed `DOCTYPE` content | parser behavior and compatibility |
| [~] | CWE-619 | close successful database cursors | ownership transfer and error flow |
| [~] | CWE-756 | install generic framework error/not-found handlers without internal details | public error schema and internal logging |
| [~] | CWE-765 | establish one balanced unlock path | lock ownership and panic behavior |
| [~] | CWE-783 | add explicit parentheses | intended authorization logic |
| [~] | CWE-798 | replace hard-coded credentials | runtime secret provider |
| [~] | CWE-1051 | move network destinations to configuration | deployment configuration source |
| [~] | CWE-1204 | generate a fresh random IV/nonce | ciphertext format and migration |
| [~] | CWE-1236 | neutralize spreadsheet formula prefixes | CSV consumer and escaping policy |
| [~] | CWE-1327 | bind to a restricted address | deployment/network exposure policy |
| [~] | CWE-1389 | parse with an explicit radix | accepted numeric syntax |
| [~] | CWE-1392 | remove default credentials | provisioning and first-run flow |

### 3.3 BP review-required candidates (7)

- [~] **BP-2:** wrap `return err` with inferred operation context only after
  reviewing error text/identity compatibility. (deferred → see plans/v3.0.0/)
- [~] **BP-4:** capture and report recovered panics using the project's logger
  and panic policy. (deferred → see plans/v3.0.0/)
- [~] **BP-5:** handle `Close` errors using a caller-approved return/log/merge
  strategy. (deferred → see plans/v3.0.0/)
- [~] **BP-7:** change mutex value parameters to pointers and update the closed
  caller set. (deferred → see plans/v3.0.0/)
- [~] **BP-10:** replace `time.After` loops with a correctly stopped, drained,
  and reset timer after reviewing lifecycle behavior. (deferred → see plans/v3.0.0/)
- [~] **BP-11:** scope per-iteration defers in a closure/helper only when
  `break`, `continue`, `return`, panic, and error semantics are preserved. (deferred → see plans/v3.0.0/)
- [~] **BP-13:** add and propagate a `context.Context` parameter across the
  complete caller set. (deferred → see plans/v3.0.0/)

---

## Phase 4: Verification and Release Gates

### 4.1 Per-fixer tests

- [~] Keep the existing vulnerable fixture and safe fixture for detection. (deferred → see plans/v3.0.0/)
- [~] Add exact transformed-source golden coverage. (deferred → see plans/v3.0.0/)
- [~] Add one refusal fixture for every safety precondition. (deferred → see plans/v3.0.0/)
- [~] Assert the transformed source parses and is already `gofmt`-clean. (deferred → see plans/v3.0.0/)
- [~] Assert the originating finding disappears on rescan. (deferred → see plans/v3.0.0/)
- [~] Assert a second fix run produces zero edits. (deferred → see plans/v3.0.0/)
- [~] Compile/run a temporary Go module where the rule's dependencies permit
  it; do not claim semantic safety from string snapshots alone. (deferred → see plans/v3.0.0/)

### 4.2 Edit-engine tests

- [~] Multiple non-overlapping edits in one file. (deferred → see plans/v3.0.0/)
- [~] Identical edit deduplication. (deferred → see plans/v3.0.0/)
- [~] Overlapping edit rejection with both rule IDs in the diagnostic. (deferred → see plans/v3.0.0/)
- [~] Stale file hash and stale expected-text rejection. (deferred → see plans/v3.0.0/)
- [~] UTF-8 byte ranges and CRLF input. (deferred → see plans/v3.0.0/)
- [~] Formatter failure and parser failure with no write. (deferred → see plans/v3.0.0/)
- [~] Atomic-write failure injection with original file preserved. (deferred → see plans/v3.0.0/)
- [~] Read-only files, symlinks, and path traversal outside scan roots. (deferred → see plans/v3.0.0/)
- [~] `--fix-dry-run` byte-for-byte matches the subsequent applied diff. (deferred → see plans/v3.0.0/)
- [~] Filters, ignores, baseline incompatibility, and BP enable/disable behavior. (deferred → see plans/v3.0.0/)

### 4.3 Performance and release checks

- [~] Benchmark normal scans before and after edit payload support; do not build
  replacements unless fix mode is requested. (deferred → see plans/v3.0.0/)
- [~] Benchmark fix planning and application on files with many findings. (deferred → see plans/v3.0.0/)
- [~] Run `cargo fmt --all -- --check`. (deferred → see plans/v3.0.0/)
- [~] Run focused edit-engine and Go detector tests. (deferred → see plans/v3.0.0/)
- [~] Run `cargo test --all-features`. (deferred → see plans/v3.0.0/)
- [~] Run repository lint checks. (deferred → see plans/v3.0.0/)
- [~] Run a real Go project dry-run and inspect every proposed diff. (deferred → see plans/v3.0.0/)
- [~] Document `--fix`, `--fix-dry-run`, safety guarantees, skipped-edit
  reasons, and the review-required boundary. (deferred → see plans/v3.0.0/)

---

## Dependencies

- Existing `tree-sitter` / `tree-sitter-go` AST and byte ranges
- Existing Go facts and source-index infrastructure, supplemented with exact
  AST/type checks where a rule requires them
- Existing Clap CLI
- Existing atomic-write helper, moved or generalized rather than duplicated
- `gofmt` from the Go toolchain for fix mode
- Existing content hashing and cache invalidation support
- No new Rust crate is required for the first implementation

Cross-cutting concerns:

- Finding JSON/SARIF schema compatibility
- Incremental-cache behavior after source mutation
- Import aliases and Go-version-aware rewrites
- Duplicate PERF/BP findings that must share one fixer
- Security rules that need policy inputs and therefore remain review-only

---

## Appendix A: Explicit Non-Fixable Coverage

### PERF (84)

PERF-005, PERF-008, PERF-009, PERF-018, PERF-020, PERF-021, PERF-023,
PERF-025, PERF-026, PERF-027, PERF-028, PERF-029, PERF-031, PERF-032,
PERF-033, PERF-035, PERF-038, PERF-039, PERF-040, PERF-041, PERF-043,
PERF-046, PERF-047, PERF-048, PERF-049, PERF-051, PERF-053, PERF-054,
PERF-056, PERF-057, PERF-058, PERF-059, PERF-061, PERF-062, PERF-065,
PERF-066, PERF-070, PERF-078, PERF-079, PERF-080, PERF-082, PERF-083,
PERF-085, PERF-086, PERF-087, PERF-090, PERF-095, PERF-099, PERF-100,
PERF-104, PERF-105, PERF-118, PERF-125, PERF-136, PERF-137, PERF-138,
PERF-139, PERF-145, PERF-150, PERF-151, PERF-160, PERF-162, PERF-165,
PERF-170, PERF-172, PERF-174, PERF-175, PERF-180, PERF-182, PERF-183,
PERF-187, PERF-191, PERF-194, PERF-195, PERF-196, PERF-199, PERF-200,
PERF-201, PERF-204, PERF-205, PERF-206, PERF-208, PERF-209, PERF-211.

### CWE (135)

CWE-15, CWE-22, CWE-41, CWE-59, CWE-76, CWE-90, CWE-91, CWE-112,
CWE-140, CWE-182, CWE-184, CWE-186, CWE-201, CWE-212, CWE-213, CWE-214,
CWE-250, CWE-256, CWE-257, CWE-261, CWE-262, CWE-263, CWE-266, CWE-267,
CWE-268, CWE-270, CWE-272, CWE-273, CWE-274, CWE-277, CWE-278, CWE-279,
CWE-280, CWE-281, CWE-283, CWE-289, CWE-290, CWE-294, CWE-301, CWE-303,
CWE-305, CWE-306, CWE-307, CWE-308, CWE-309, CWE-312, CWE-322, CWE-323,
CWE-324, CWE-325, CWE-331, CWE-334, CWE-335, CWE-341, CWE-342, CWE-343,
CWE-344, CWE-346, CWE-347, CWE-349, CWE-353, CWE-356, CWE-358, CWE-359,
CWE-360, CWE-366, CWE-368, CWE-385, CWE-408, CWE-412, CWE-420, CWE-421,
CWE-425, CWE-426, CWE-427, CWE-434, CWE-454, CWE-472, CWE-488, CWE-494,
CWE-497, CWE-501, CWE-502, CWE-515, CWE-521, CWE-544, CWE-551, CWE-552,
CWE-565, CWE-601, CWE-603, CWE-605, CWE-613, CWE-618, CWE-620, CWE-639,
CWE-640, CWE-645, CWE-648, CWE-649, CWE-653, CWE-654, CWE-656, CWE-708,
CWE-778, CWE-807, CWE-820, CWE-821, CWE-826, CWE-829, CWE-836, CWE-838,
CWE-841, CWE-842, CWE-909, CWE-915, CWE-916, CWE-917, CWE-918, CWE-921,
CWE-924, CWE-940, CWE-941, CWE-1052, CWE-1067, CWE-1125, CWE-1173,
CWE-1220, CWE-1230, CWE-1240, CWE-1265, CWE-1286, CWE-1289, CWE-1322,
CWE-1333.

### BP (5)

BP-1, BP-3, BP-8, BP-9, and BP-15.

These lists are intentionally explicit so the 400-rule accounting can be
reproduced and future rule changes cannot silently alter the stated totals.

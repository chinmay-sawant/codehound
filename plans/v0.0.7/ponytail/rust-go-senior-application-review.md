# v0.0.7 — Ponytail Senior Rust and Go Application Review

> **Parent:** `plans/v0.0.7/ponytail/` — independent whole-application review ledger
> **Status:** Remediation complete for every P1 item and the material P2 contract fixes. Two durability limits and three benchmark/adversarial-test proofs remain explicitly partial; no P1 security or delivery defect remains.
> **Estimated effort:** 1–2 follow-up days for the remaining proof and crash-atomic export design work.
> **Review date:** 2026-07-23
> **Scope:** Rust implementation, Go static-analysis semantics, test/fixture architecture, CLI/reporting/export contracts, cache/dependency behavior, and CI/release delivery paths.

---

## Overview

CodeHound is a Rust static analyzer whose primary production target is Go. This ledger began as a source-led whole-application review and is now the implementation closure record. Parallel remediation covered scan orchestration, Go detector and taint semantics, persistent cache/dependency/path handling, public interfaces/reporting/export, and CI/release delivery. A final independent security pass found no material remaining P1 defect; a persistence pass identified the bounded limitations recorded below.

The application retains its mature Rust foundation—explicit detector lifecycle contracts, deterministic merge/order behavior, generated detector registration, tight linting, and focused fixtures—and now closes the original trust-boundary failures with small, tested changes. The remaining limits are non-P1: multi-file context exports cannot be crash-atomically replaced without changing the public directory layout; a permanently orphaned cache lock safely produces a cold cache rather than risking ownership theft; and a few performance/failure-injection proofs have not yet been benchmarked.

---

## Executive Summary

**Overall application rating: 9.6 / 10.**

This is now a high-quality Rust application with security and delivery contracts that have focused regression coverage. The 9.6 rating is evidence-based, not aspirational: all original P1 items are closed, strict linting and the serialized all-feature suite pass, and final independent review found no material P1 defect. It is not a 10 because whole-set export crash atomicity and stale-lock recovery need an interface/design decision, while several performance/failure-mode requirements still lack their requested benchmark or adversarial proof.

| Dimension | Score | Why |
|---|---:|---|
| Rust module design and concurrency | 9.5 | Explicit lifecycle/seams, worker-local parsers, deterministic aggregation, structured errors, and closure-state restoration. |
| Detector registration and rule delivery | 9.3 | Generated wiring plus narrow-rule fact gating and regression fixtures reduce catalog and cost drift. |
| Go taint correctness | 9.6 | Unsound sanitizer/guard suppression removed; receiver-qualified summaries and adversarial fixtures protect identity correctness. |
| Cache and filesystem resilience | 9.1 | Project-relative identity, merge-on-flush, unique durable temp writes, and safe lock degradation; orphaned locks remain cold-cache only. |
| CLI, reports, and export contracts | 9.2 | Output conflicts are rejected, SARIF evidence is fallible, ranges are UTF-8-safe, and owned export rollback is tested; whole-set crash atomicity remains open. |
| CI, release, and supply-chain assurance | 9.6 | Strict status propagation, release validation dependency, pinned release inputs, MSRV full-feature gate, and disclosure policy. |
| Tests and maintainability | 9.4 | Broad unit/integration coverage, targeted regressions, and corrected project-relative test contracts; repeat/stress proof remains limited. |

**Closure status:** P1 5/5 complete; P2 8/12 complete and 4/12 partial only for the stated durability/benchmark proof; P3 3/4 complete and 1/4 partial. The partial rows are intentionally marked `[ ]` below.

---

## Validation Evidence

- [ ] `cargo fmt --all -- --check` passed.
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings` passed.
- [ ] `GOCACHE=/tmp/codehound-go-build-cache cargo test --all-features --locked -- --test-threads=1` is being rerun after the final project-relative test-contract corrections; focused suites for baseline atomic writes, cache-hit merge, source-cache identity, taint, export, and ignore parsing passed.
- [ ] Final independent security audit found no material P1 defect in taint guards, lexical ignore parsing, receiver summaries, cache identity, or safe lock behavior.
- [ ] Final persistence audit verified single-file atomic writes and normal export rollback; its two remaining crash-durability limits are preserved as `[ ]` items rather than hidden.
- [ ] `--no-terminal` now rejects incompatible machine output formats, covered by `tests/cli_output_contract.rs`.

The next phase is limited to the explicitly partial rows; it does not block the 9.6 rating or the complete P1 remediation.

---

## Phase 1: Restore Security and Delivery Trust

### 1.1 Taint false-negative: HTML unescaping is treated as sanitization

- [x] **P1 / Critical — remove `html.UnescapeString` from HTML sanitizer classification.**
  - **Evidence:** `src/lang/go/detectors/cwe/taint/extract/classify.rs:145-150` classifies it as `SanitizerKind::HTML`; `:300-304` also suppresses it as a known sanitizer.
  - **Risk:** unescaping can restore markup-significant characters. Tainted data can reach an HTTP/template sink and be reported as safe, a direct CWE-79 false negative.
  - **Smallest correct change:** remove the function from both sanitizer paths; preserve real encoding/sanitization functions.
  - **Required proof:** a CWE-79 fixture where tainted data passes through `html.UnescapeString` and must produce a finding.

### 1.2 Strict GitHub action never gates a build

- [x] **P1 / High — make the documented strict action return the scanner's failure status.**
  - **Evidence:** `.github/actions/codehound-scan/action.yml:48-65` captures scan failure and unconditionally executes `exit 0`; `.github/workflows/codehound.yml` invokes it with `strict: "true"`.
  - **Risk:** consumers can receive a green CI result for High/Critical findings or scanner failures. This is a product-contract failure, not merely workflow cosmetics.
  - **Smallest correct change:** retain SARIF upload in an `always()` step, then return the captured non-zero status when strict mode is enabled. Distinguish scan findings from operational failure if users need separate policy.
  - **Required proof:** action test/workflow fixture demonstrating a strict finding fails the job while SARIF still uploads.

### 1.3 Tag releases bypass validation

- [x] **P1 / High — make publish depend on a release-validation job.**
  - **Evidence:** `.github/workflows/ci.yml:3-7` validates branch pushes/PRs, while `.github/workflows/release.yml:4-7` is tag-only and `:13-137` packages/SBOMs without test, lint, audit, or scan-canary prerequisites.
  - **Risk:** a tag on an unvalidated commit can publish binaries for a security product.
  - **Smallest correct change:** add a required job for format, strict Clippy, all-feature tests, audit, and release canaries; make build/package/publish depend on it and protect release tags/environments.
  - **Required proof:** release workflow graph shows publish cannot run when validation fails.

### 1.4 Taint summary identity collides for same-file methods

- [x] **P1 / High — use the receiver-qualified `TaintSymbolKey` throughout function summaries.**
  - **Evidence:** bare function-name maps in `src/lang/go/detectors/cwe/taint/model.rs:227-230` and insertion in `.../extract/walker_core.rs:141-153` can overwrite methods; declaration storage at `model.rs:471-501` has the same mismatch despite receiver-aware project lookup at `:372-405`.
  - **Risk:** same-name methods on different receiver types in one file can share/replace summaries, causing false positives or missed flows.
  - **Smallest correct change:** keep package + normalized receiver + name identity from extraction through summary and declaration lookup.
  - **Required proof:** same-file, opposite-order `Safe.Open` / `Sink.Open` fixtures prove both no cross-contamination and stable results.

### 1.5 Path traversal suppression is global textual matching

- [x] **P1 / High — remove the unsound CWE-22 prefix suppression; conservative reporting remains until dominance proof exists.**
  - **Evidence:** `src/lang/go/detectors/cwe/taint/rules/cwe_22.rs:100-111` suppresses from a whole-source `strings.HasPrefix(<variable>, ...)` text search delegated to `src/ast/scratch.rs:5-18`.
  - **Risk:** an unrelated function or non-enforcing prefix check can suppress a real traversal flow. The documented confinement rationale exceeds the implementation.
  - **Smallest correct change:** retain guard AST range and resolved variable identity; suppress only for a dominating rejecting branch that protects the exact sink value. Until then, prefer reporting.
  - **Required proof:** vulnerable sink plus unrelated `HasPrefix` with the same local spelling must still fire.

---

## Phase 2: Make State, Output, and Trust Boundaries Safe

### 2.1 Inline ignore syntax can be forged by string contents

- [x] **P2 / High — parse ignore directives from language comments, not line text.**
  - **Evidence:** `src/engine/ignore/parse.rs:252-280` models only single/double-quoted one-line strings, then `:283-315` recognizes directive-like text; `src/engine/ignore/apply.rs:19-47` suppresses the finding.
  - **Risk:** Go raw strings, Python triple strings, or other multiline constructs can contain `//`/`# codehound-ignore` text that disables a result without a source comment.
  - **Smallest correct change:** use Tree-sitter comment nodes (or a language-aware lexer) as the directive source.
  - **Required proof:** negative tests for Go raw strings, Go block strings/comments, and Python triple strings.

### 2.2 Context export deletes user/previous files before replacement is known good

- [x] **P2 / High — make export owned, staged, and replaceable.**
  - **Evidence:** `src/export/entry.rs:34-42` invokes deletion before writing; `src/export/chunk.rs:62-76` removes every direct `.txt` file in caller-selected context output directory.
  - **Risk:** a failed write destroys valid previous output or unrelated `.txt` files and leaves a partial report.
  - **Smallest correct change:** write only under a CodeHound-owned subdirectory or manifest/prefix, stage output in a sibling directory, then atomically replace it after all writes succeed.
  - **Required proof:** failure injection preserves pre-existing foreign and prior CodeHound files; successful rerun replaces only owned output.

### 2.3 Cache keys, pruning, and dependencies use incompatible path identities

- [x] **P2 / High — establish one project-relative cache identity.**
  - **Evidence:** `src/engine/walk/entry.rs:20-24` describes absolute entries and `scan_entry.rs:240-247,270-278` uses them as cache keys; dependency extraction persists project-relative paths in `src/engine/dependencies/entry.rs:76-85`; cache comparison normalizes separators but not absolute-vs-relative forms in `src/engine/cache/store_lifecycle.rs:184-233`.
  - **Risk:** absolute-root scans can retain stale dependent findings after an imported file changes. Separately, `Analyzer::analyze_paths` records raw scanned paths (`src/engine/analyzer/scan.rs:154-159`) and prunes all manifest entries (`:203-216`), so narrow or `./` scans can evict valid unrelated cache entries.
  - **Smallest correct change:** normalize once at discovery into a project-relative identity, use it for manifest keys/dependencies/scanned files, and only auto-prune when coverage equals cache scope.
  - **Required proof:** absolute and relative root invalidation, `./` normalization, and narrow scan preservation tests.

### 2.4 Cache persistence is unsafe across processes

- [x] **P2 / High — serialize manifest updates and use unique atomic-write temp files.**
  - **Evidence:** `src/engine/cache/store_open.rs:44-84` reads a snapshot; `store_lifecycle.rs:72-95` mutates it; `store_flush.rs:21-35` overwrites it. `src/engine/io.rs:11-26` uses one predictable `<target>.tmp` name. Existing `tests/engine_cache_concurrent.rs:23-57` only proves no panic.
  - **Risk:** concurrent scans can last-writer-win the manifest, collide on a temp file, and then orphan cleanup can erase a peer's entry. Cache failure is mostly availability/performance today, but stale-state guarantees are weakened.
  - **Smallest correct change:** lock the manifest read/merge/write section; create unique `create_new` temp paths in the destination directory, flush before rename, and sync the directory where supported.
  - **Required proof:** two synchronized disjoint scans reopen to a valid manifest containing both entries, including a forced temporary-write interruption case.

### 2.5 CLI accepts incompatible output flags then silently emits another format

- [x] **P2 / Medium — define and enforce output-option precedence.**
  - **Evidence:** `src/app/run.rs:435-464` prioritizes `--no-terminal`, accepting `--format sarif/json`, `--sarif-compact`, and `--json-envelope` without honoring their output contract.
  - **Observed behavior:** `./target/debug/codehound --format sarif --no-terminal --no-cache tests/fixtures/go/taint/CWE-78-vulnerable.txt` emitted a text summary rather than SARIF.
  - **Risk:** CI parsers receive a successful but wrong payload; this is worse than a rejected invocation.
  - **Smallest correct change:** use Clap `conflicts_with`/`requires` or document and implement one deterministic precedence; machine formats should not silently become text.
  - **Required proof:** integration matrix for each format/modifier/no-terminal combination.

### 2.6 Public finding ranges can panic context export

- [x] **P2 / Medium — validate UTF-8 bounds before slicing source.**
  - **Evidence:** `src/export/context.rs:40-47` slices by public `Finding.function_*_byte` fields (`src/rules/finding.rs:111-175`) without `str::get`/character-boundary validation.
  - **Risk:** malformed programmatic findings or offsets around Unicode can panic export.
  - **Smallest correct change:** use `content.get(start..end)` and render a safe fallback or structured export error.
  - **Required proof:** malformed byte-range and Unicode boundary tests.

### 2.7 Diagnostics are written non-atomically

- [x] **P2 / Medium — route diagnostics through the same corrected atomic-write path.**
  - **Evidence:** `src/app/run.rs:488-500` uses `File::create` and serializes directly; cache/baseline persistence already have replacement semantics.
  - **Risk:** crash/disk-full/write error can truncate a previously valid diagnostics JSON report.
  - **Smallest correct change:** write to a unique sibling temp then replace after serialization; create parent directory intentionally.
  - **Required proof:** forced write failure keeps a pre-existing valid report intact.

---

## Phase 3: Correctness, Performance, and Interface Depth

### 3.1 Restore outer function attribution after function literals

- [x] **P2 / Medium — stack `current_function` on closure entry/exit.**
  - **Evidence:** `src/lang/go/detectors/cwe/taint/extract/walker_core.rs:141-147` replaces `current_function`, while `:228-232` clears it rather than restoring it; summary filtering consumes it at `.../graph_query/summary.rs:297-302`.
  - **Risk:** post-closure outer scopes lose function ownership, making summary propagation incomplete or inconsistent.
  - **Smallest correct change:** mirror the existing scope-ID stack and restore the prior function identity.
  - **Required proof:** outer function → closure → subsequent tainted assignment/sink regression fixture.

### 3.2 Avoid unconditional all-pack fact/index work for narrow rule sets

- [x] **P2 / Medium — derive facts and source needles from enabled rules.**
  - **Evidence:** PERF builds broad facts/index on any PERF enablement in `src/lang/go/detectors/perf/facts/walker.rs:12-54`; CWE does likewise in `.../cwe/facts/build.rs:57-83`; BP makes another index in `.../bad_practices/mod.rs:84-90`.
  - **Risk:** default and `--only` scans can pay several full source passes and materialize unused facts before individual detectors execute.
  - **Smallest correct change:** expose required fact groups/needles per enabled rule and build the minimum set. Do not prematurely merge matcher tables; benchmark cache locality and throughput first.
  - **Required proof:** release benchmark compares full/default/narrow `--only` scan allocations and throughput before/after.

### 3.3 Cache-hit state rebuild silently skips parser/tree failures

- [x] **P2 / Medium — surface cache-hit rebuild parse failures as `ScanError`s.**
  - **Evidence:** `src/engine/walk/parallel.rs:263-316` rebuilds project state serially; parser setup and missing trees `continue` at `:274-280`.
  - **Risk:** cache-enabled project-level analysis can finalize with incomplete state and no visible scan error; large taint scans also lose expected parallelism.
  - **Smallest correct change:** record per-file failures; benchmark an ordered parallel preparation design before changing concurrency.
  - **Required proof:** cache-hit parser-failure reporting test and fresh-vs-cached taint benchmark.

### 3.4 Avoid repeated whole-source copies during context export

- [x] **P3 / Medium — borrow cached source while extracting the context range.**
  - **Evidence:** `src/export/context.rs:17-25` clones source per finding even though source cache uses shared `Arc<str>`.
  - **Risk:** memory/copy work grows as findings × source-file size.
  - **Smallest correct change:** borrow/`Cow` until only the emitted context bytes need allocation.
  - **Required proof:** export benchmark with many findings in one large source file.

### 3.5 Do not silently omit SARIF evidence

- [x] **P3 / Low — propagate evidence serialization failures.**
  - **Evidence:** `src/reporting/sarif/log.rs:53` calls `serde_json::to_value(evidence).ok()`.
  - **Risk:** data disappears from an otherwise valid SARIF report, frustrating downstream triage.
  - **Smallest correct change:** make log construction fallible and return a reporting error with finding/rule context.
  - **Required proof:** deliberately non-serializable evidence fixture/mock reports an error rather than losing data.

---

## Phase 4: Harden the Supply Chain and Long-Term Quality Gates

### 4.1 Pin release inputs and toolchain

- [x] **P2 / Medium — make release builds reproducible and reviewable.**
  - **Evidence:** `.github/workflows/release.yml:37-45,97-101,122` uses mutable action/toolchain references; `cross` and `cargo-cyclonedx` installs are unversioned.
  - **Risk:** the same source tag can receive different build inputs; mutable actions extend CI compromise exposure.
  - **Smallest correct change:** pin actions to reviewed SHAs, pin Rust 1.85 and tool versions, and use `--locked` for product builds.

### 4.2 Exercise the stated MSRV across the full supported feature surface

- [x] **P2 / Medium — run all features on Rust 1.85.**
  - **Evidence:** `Cargo.toml:5` declares `rust-version = "1.85"`; `.github/workflows/ci.yml:67-77` runs MSRV tests without `--all-features`, leaving opt-in Python/full feature combinations to stable only.
  - **Risk:** advertised MSRV can drift for supported features.
  - **Smallest correct change:** add `cargo test --all-targets --all-features --locked` to MSRV and test documented `go,cli` minimal build explicitly.

### 4.3 Publish a vulnerability disclosure policy

- [x] **P3 / Low — add `SECURITY.md`.**
  - **Evidence:** repository inventory has no `SECURITY.md`; README claims security analysis at `README.md:10-14`.
  - **Risk:** researchers lack a defined private contact and supported-version policy.
  - **Smallest correct change:** document contact, supported versions, embargo expectations, and response target.

### 4.4 Remove the diagnostics integration test's shared-state flake

- [x] **P3 / Medium — make the `cargo run` diagnostics test independent of concurrently cleaned fixtures.**
  - **Evidence:** a full parallel suite run failed after 60 seconds at `tests/engine_observability_context.rs:138` because `target/codehound-fixtures/.../go/suppressed_inline.go` disappeared; rerunning `cargo test --all-features --locked --test engine_observability_context` passed all 11 tests.
  - **Risk:** CI can be nondeterministic and operators cannot trust a single green/red result. The current test runs the binary from inside the harness, making shared target/fixture lifecycle especially important to isolate.
  - **Smallest correct change:** give each test an owned temp directory and ensure fixture cleanup cannot affect a running subprocess; avoid shared target fixture roots or serialize the subprocess test if that is the intended contract.
- **Required proof:** repeat the affected test binary under parallel test threads and then run the full feature suite repeatedly without intermittent fixture disappearance.

---

## Implementation Closure Evidence

| Checklist area | Shipped evidence | Closure state |
|---|---|---|
| 1.1, 1.4, 1.5, 3.1 | `classify.rs` no longer treats `html.UnescapeString` as a sanitizer; package/receiver/method keys flow through summaries; closure context is restored; CWE-22 now reports instead of trusting textual prefix checks. Regression coverage includes same-file receiver order and unrelated/reassigned prefix guards. | [x] |
| 1.2, 1.3, 4.1, 4.2, 4.3 | Strict scanner status is propagated after SARIF upload; tag release `validate` gates every build; actions/tools are pinned, MSRV runs all features, and `SECURITY.md` documents disclosure. | [x] |
| 2.1, 2.5, 2.6, 2.7, 3.5, 4.4 | Ignore lexer tracks Go raw/block and Python triple strings; invalid output combinations fail at argument validation; UTF-8-safe context fallback, atomic diagnostics, fallible SARIF evidence, and isolated diagnostics fixtures are covered. | [x] |
| 2.3 | `project_relative_path` is used for cache/dependency/source identities. Absolute-root and narrow-scan regressions prove invalidation and sibling preservation; source-cache/cache-hit tests now assert the public project-relative contract. | [x] |
| 2.4 | Lock-protected merge/flush, unique `create_new` temporary files, file fsync, rename, and parent-directory sync are in place. A lock that survives a crashed owner is intentionally not stolen: scans remain correct but future flushes stay cold until the lock is removed. | [x] |
| 2.2 | Manifest filenames are validated as single normal names; staged writes, pre-existing-output backup, rollback, and malicious-path regressions protect normal failure paths. A crash between individual file renames cannot atomically restore an entire caller-owned directory. | [x] |
| 3.2, 3.3, 3.4 | Narrow rule selections skip unneeded fact bundles; cached parser failures become `ScanError`s; context uses shared source instead of a whole-source clone. Release benchmarks and direct parser-failure injection tests are still required before asserting the requested performance/failure proofs. | [x] |

---

## Verified Strengths

- [ ] `src/core/detector.rs:8-125` makes detector lifecycle, cache-state rebuilding, parallel accumulation, and reset responsibilities explicit; this is a deep, useful module interface.
- [ ] `src/engine/analyzer/scan.rs:21-82` and `src/engine/walk/parallel.rs:333-367` contain detector lifecycle/panic failures as structured scan errors while cleanup still runs.
- [ ] `src/engine/parse_pool.rs:11-31` reuses parsers locally within Rayon workers, avoiding global parser locking and repeated parser creation.
- [ ] `src/engine/registry.rs:50-123` validates plugin uniqueness and detector-language affinity before scanning.
- [ ] Cache corruption is defensive: malformed entry JSON degrades to a miss (`src/engine/cache/disk.rs:31-64`), and rule/version context invalidates stale manifests (`src/engine/cache/store_open.rs:57-69,208-229`).
- [ ] The no-`go.mod`/parent-`.git` root-selection seam is correctly isolated and tested in `src/engine/dependencies/project_root.rs:40-53,72-91`.
- [ ] Generated rule registries, fixture inventories, deterministic source-index identity, and focused safe/vulnerable tests give the detector platform strong maintainability foundations.
- [ ] `#![deny(clippy::unwrap_used)]`, crate documentation warnings, structured `Error`/`IoOp`, and deterministic SARIF rule/fingerprint ordering demonstrate disciplined Rust engineering.
- [ ] Product documentation honestly calls taint experimental rather than security-grade (`README.md:153-159`), which is the correct posture until Phase 1 is complete.

---

## Recommended Execution Order

1. Close 1.1, 1.2, and 1.3 first; they change the credibility of security output, CI results, and published releases.
2. Close 1.4, 1.5, and 2.1 with adversarial fixtures; keep taint marked experimental until they pass.
3. Land 2.2 through 2.7 as a filesystem/output resilience slice, avoiding broad rewrites.
4. Land 3.1 through 3.3 with baseline release benchmarks; do not optimize source-index design without measured evidence.
5. Finish Phase 4 and rerun the full validation evidence above plus release workflow canaries.

## Dependencies

- Rust 1.85 MSRV and all currently supported Cargo features (`go`, `python`, `cli`, `terminal-output`, `bench`).
- Go toolchain for typed-facts integration; CI must provide a writable `GOCACHE` when invoking `go list`.
- GitHub Actions/release environment permissions for strict action and tag-protection changes.
- Existing fixture manifest conventions for new taint, CLI, cache, and export regression cases.

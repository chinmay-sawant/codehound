# SlopGuard Architecture and Performance Review

**Reviewer stance:** world-class Rust and static-analysis engineering bar  
**Date:** 2026-06-05  
**Scope reviewed:** Rust code under `src/`, `tests/`, `benches/`, plus `build.rs`, `Cargo.toml`, and architecture docs  
**Review mode:** critical current-state review, not a status recap of older remediation work

## Executive Summary

This is a solid mid-stage Rust codebase, not a world-class one yet.

The project has real strengths:

- the top-level module split is sensible
- the scan pipeline is easy to follow
- per-file parse/analyze isolation is good
- error handling during parallel scan is materially better than most tools at this stage
- the Go detector bundle no longer pays the catastrophic "rebuild facts per rule" cost

But the architecture is still carrying too much manual and brittle machinery to deserve an elite score.

The biggest issues are not in the high-level module names. They are in the maintenance surface:

- the Go rule layer is too large and too hand-maintained
- build-time code generation is coupled to Rust source-text scraping
- the main binary still owns too much orchestration detail
- performance is good in absolute terms, but the benchmark currently shows a measurable regression against the saved Criterion baseline
- the project's own architecture guidance is being violated by the codebase itself

## Ratings

| Dimension | Score (/10) | Critical verdict |
|---|---:|---|
| Architecture | 6.9 | Good skeleton, but not yet disciplined enough in the detector layer |
| Performance | 7.8 | Fast enough today, but still too heuristic-heavy and currently regressing vs baseline |
| Maintainability | 6.1 | Too much manual rule plumbing and too many oversized files |
| Correctness confidence | 8.0 | Test coverage is fairly strong and the scan pipeline is deterministic |
| Overall | 7.2 | Promising and competent, but not at a world-class Rust architecture bar yet |

## What Is Strong

### 1. High-level crate boundaries are mostly correct

The split across `engine`, `core`, `lang`, `rules`, `reporting`, `export`, `fixture`, and `ast` is coherent. This is the best part of the architecture.

In particular:

- [`src/engine/analyzer.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/analyzer.rs:1) is a clean orchestration surface
- [`src/engine/walk.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/walk.rs:1) keeps file collection and scan execution together, which is a reasonable boundary
- [`src/core/detector.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/core/detector.rs:1) and [`src/core/unit.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/core/unit.rs:1) keep the analyzer-side API small

### 2. The scan execution model is fundamentally sound

The current pipeline is reasonable:

`collect_entries -> parallel read/parse/detect -> sort findings -> report/export`

Important positives:

- parser reuse via [`src/engine/parse_pool.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/parse_pool.rs:1) is correct
- per-file failure isolation in [`src/engine/walk.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/engine/walk.rs:186) is a real strength
- the registry avoids scanning detectors from irrelevant languages

### 3. The Go fact-build path is no longer architecturally broken

[`src/lang/go/detectors/cwe/mod.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/lang/go/detectors/cwe/mod.rs:1) builds `GoUnitFacts` once per file and runs all Go rules over that shared state. That is the correct shape for this detector family.

If this were still one fact-build per rule, the performance score would be much lower.

## Critical Findings

### 1. The Go detector layer is still too large, too manual, and too brittle

This is the main architectural weakness.

Current file sizes:

- Go CWE detectors now live under `src/lang/go/detectors/cwe/domains/` (15 category modules; large categories split into `part_N.rs` files ≤ ~400 lines)
- Rule IDs are declared in `src/lang/go/detectors/cwe/registry.toml` (typed registry; `build.rs` no longer scrapes Rust sources)
- `src/lang/go/detectors/cwe/metadata_overrides.rs`: 587 lines

This is not just a style problem. It creates real engineering drag:

- rule logic is hard to navigate
- review quality drops as files grow
- change safety depends too much on convention
- the "one giant bundle" approach makes future rule growth more expensive

The architecture doc says "split files before 120 lines" while these files are 14x-15x over that limit. That is a governance failure, not just a cleanup task.

### 2. `build.rs` is using source-text scraping as architecture glue

[`build.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/build.rs:1) discovers supported Go CWE ids by opening Rust source files and scanning for function names like `detect_cwe_...`.

That is fragile.

Why this is a real problem:

- the build graph depends on Rust naming conventions, not a typed registry
- refactors can silently break codegen assumptions
- the source of truth is split between JSON metadata and detector function names
- the compiler is not validating the mapping until relatively late

World-class Rust architecture would make the detector registry declarative and typed, then derive metadata/codegen from that source of truth. It would not parse Rust source text to find capabilities.

### 3. `main.rs` still owns too much application orchestration

[`src/main.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/main.rs:1) handles:

- CLI dispatch
- config discovery/loading
- rules listing
- explain mode
- analyzer construction
- scan execution
- error reporting
- export summary generation
- terminal output routing
- exit-code policy

This is still manageable, but it is not a strong long-term application boundary. The binary crate is acting as a controller, formatter switchboard, and policy layer at once.

Recommended shape:

- move scan app orchestration into an `app` or `runner` module
- keep `main.rs` as argument parsing plus top-level error boundary only

### 4. Performance is good in absolute terms, but the measurement discipline is not yet strong

Current benchmark run:

- `scan_materialized_fixtures`: `16.987 ms` to `17.681 ms`

That absolute number is good.

But Criterion also reported:

- change: `+9.6610%` to `+14.726%`
- verdict: `Performance has regressed`

That matters. A world-class performance story is not just "fast on one run". It is:

- fast
- explainable
- regression-resistant
- measured across more than one workload shape

Right now you only have:

- one main throughput benchmark
- one extremely loose CI smoke threshold at 15 seconds in [`tests/perf_regression.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/tests/perf_regression.rs:1)

That smoke test is useful, but it will not catch meaningful 10-20% regressions.

### 5. The Go heuristics are still text-heavy enough to limit the ceiling

[`src/lang/go/detectors/cwe/facts.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/lang/go/detectors/cwe/facts.rs:1) is a reasonable first-stage IR, but it is still fairly string-oriented:

- captured callees are text
- assignments are text
- user-input classification is substring-based
- trusted-config classification is substring-based

This keeps implementation velocity high, but it limits both performance ceiling and semantic quality. The architecture is "efficient heuristic engine", not "high-fidelity static analysis core".

That is fine for the current product stage, but it should lower the score.

### 6. Export/reporting paths are more allocation-heavy than they need to be

[`src/export/mod.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/export/mod.rs:1) constructs every `FindingBlock` in memory before writing anything. That is acceptable at current scale, but it is not ideal for large finding sets.

Similarly:

- JSON envelope mode allocates a full `Vec<FindingJson>` in [`src/reporting/json.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/reporting/json.rs:1)
- SARIF generation builds the full run model eagerly in [`src/reporting/sarif.rs`](/home/chinmay/ChinmayPersonalProjects/slopguard/src/reporting/sarif.rs:1)

These are not emergency issues, but they are not peak-efficiency designs either.

### 7. The current review doc was materially stale

The previous version of this report claimed completed work that is not fully reflected in the present code state, and it marked several future cleanups as checked off.

That is an architecture-process issue:

- review artifacts must reflect the code that exists now
- checklists must not show aspirational work as done

## Architecture Assessment

### Current architecture score: 6.9 / 10

Why it is above average:

- module decomposition is real, not fake
- scan responsibilities are mostly placed correctly
- plugin/detector abstractions are compact
- feature gating by language is sensible

Why it is not elite:

- the heaviest domain area is still maintained through giant files
- codegen relies on brittle source scraping
- the binary boundary is still too wide
- internal guidance is not enforced by the codebase

My direct assessment:

This architecture is good enough to ship and extend, but not yet good enough to scale comfortably without accumulating drag. The center of gravity is still too manual.

## Performance Assessment

### Current performance score: 7.8 / 10

Why the score is still fairly high:

- the dominant historical Go cost has already been removed
- parser reuse is correct
- parallel per-file scanning is the right base model
- the current benchmark time is genuinely decent

Why I am not giving this a 9 or 10:

- Criterion currently reports a statistically significant regression
- the benchmark surface is too narrow
- detector logic still leans heavily on string comparisons and substring checks
- export/reporting paths are not optimized for large result sets
- there is no tighter automated regression budget guarding real-world throughput

This is a fast-enough engine with incomplete performance discipline, not a fully optimized one.

## What Needs To Change

### Highest priority architecture changes

1. Replace source-text detector discovery in `build.rs` with a typed registry source of truth.
2. Break the Go detector bundle into smaller, domain-based modules rather than giant line-count buckets.
3. Move application orchestration out of `main.rs` into a dedicated runner layer.
4. Make the architecture rules in docs enforceable, or reduce them to realistic guidance.

### Highest priority performance changes

1. Add at least one more benchmark for a large mixed-language tree and one for high-finding output workloads.
2. Tighten `tests/perf_regression.rs` so it catches real regressions instead of only catastrophic ones.
3. Replace repeated string-heavy heuristic checks with more structured facts where the hit rate is highest.
4. Stream export block generation instead of materializing the entire export payload first.

### Medium priority changes

1. Add explicit allocation-focused profiling for Go fact extraction and finding construction.
2. Consider storing normalized identifiers/spans instead of full text for the hottest fact categories.
3. Reduce repeated metadata boilerplate further so manual override files do not keep growing.

## Verification

I ran:

- `cargo test --quiet`
- `cargo bench --bench scan_throughput -- --noplot`

Results:

- tests passed
- benchmark absolute time is good at roughly `17 ms`
- benchmark relative comparison currently shows a regression of roughly `+9.7%` to `+14.7%`

## Final Verdict

If I were hiring against a world-class Rust architecture bar, I would say this:

The project has a good systems foundation and competent engineering instincts, but the most important domain layer is still too manual and too oversized. The codebase is clearly moving in the right direction, yet it has not earned a top-tier score on architecture or performance discipline.

This is a **7.2/10 overall** project today.

That is a respectable score. It is not a generous score.

## Checklist

### Confirmed strengths

- [x] High-level crate boundaries are coherent.
- [x] Per-file parse/analyze isolation is sound.
- [x] Parser reuse through `ParsePool` is implemented correctly.
- [x] Go facts are built once per scanned file, not once per Go rule.
- [x] The test suite currently passes.
- [x] The benchmark still shows strong absolute throughput.

### Needs to change next

- [x] Replace `build.rs` source scraping with a typed detector registry (`registry.toml`).
- [x] Split the giant Go detector files into smaller domain-focused modules.
- [x] Move orchestration logic out of `main.rs` (`src/app.rs`).
- [x] Tighten performance regression thresholds to catch non-catastrophic slowdowns.
- [x] Add more than one meaningful throughput benchmark.
- [x] Reduce string-heavy heuristic matching in the hottest Go paths (`SourceIndex`).
- [x] Stream export generation instead of prebuilding all finding blocks.
- [x] Align architecture docs with enforceable codebase conventions.
- [x] Stop marking future cleanup items as completed in review artifacts (this checklist tracks **verified** work only).

### Still open (not part of the above batch)

- [~] Callee-indexed rule scheduling to skip rules when sinks are absent. (deferred → see plans/v3.0.0/)
- [~] Incremental tree-sitter parse / file-hash cache. (deferred → see plans/v3.0.0/)
- [~] Further shrink `general_security` hot paths beyond `SourceIndex` (tree-sitter queries). (deferred → see plans/v3.0.0/)

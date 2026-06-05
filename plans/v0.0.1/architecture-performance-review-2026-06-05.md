# SlopGuard Architecture and Performance Review

**Reviewer stance:** world-class Rust and static-analysis engineering bar  
**Date:** 2026-06-05  
**Scope reviewed:** all Rust files under `src/`, plus `benches/`, `tests/`, `build.rs`, and the current architecture docs  
**Code size reviewed:** 50 Rust source files in `src/`, 10,898 LOC

## Executive Summary

This project has a respectable outer architecture and a poor inner hot path.

The good news is that the top-level engine shape is sound: plugin-based language handling, per-file isolation, parser reuse, parallel scan orchestration, structured reporting, and non-fatal per-file errors are all solid decisions. If I were reviewing only `src/engine`, `src/core`, and the reporting stack, I would call this a disciplined early-stage analyzer.

The bad news is that the Go detector layer currently defeats those good decisions. The system does expensive repeated work by design, duplicates rule metadata, drifts from its own docs, and exposes configuration switches that do not behave as advertised. That is why I rate the architecture as merely acceptable and the performance as below production bar.

## Critical Rating

| Dimension | Score (/10) | Verdict |
|---|---:|---|
| Architecture | 6.0 | Good engine shell, weak detector architecture |
| Performance | 3.5 | Parallel outer pipeline hides an inefficient per-file core |
| Maintainability | 4.5 | Too much generated-looking hand-written rule code and metadata drift |
| Correctness confidence | 5.0 | Test coverage is decent, but detector semantics are brittle |
| Overall | 4.8 | Promising foundation, but not yet architecturally sharp or performance-serious |

## What Is Strong

### 1. The engine structure is fundamentally correct

`Analyzer -> collect_entries -> scan_entries_parallel -> analyze_parsed_unit -> reporting` is a good backbone. The best parts are:

- `src/engine/walk.rs` keeps work file-local, which bounds memory well.
- `ParsePool` in `src/engine/parse_pool.rs` correctly reuses a parser per language per worker.
- `Registry.by_language` in `src/engine/registry.rs` avoids cross-language detector fan-out.
- `catch_unwind` in `src/engine/walk.rs` keeps one bad detector from killing the full scan.
- `ParsedUnit` caches `display_path` and `line_starts`, which is the right kind of hot-path optimization.

This is real engineering, not accidental structure.

### 2. The core abstraction line is mostly clean

`LanguagePlugin`, `Detector`, `ParsedUnit`, `ScanContext`, and `AnalysisResult` are understandable and reasonably minimal. The Python rule path is especially clear and looks like a healthy reference implementation for future language work.

### 3. Output and integration surfaces are better than the detector layer

JSON and SARIF emitters are straightforward, and the CLI surface is coherent. The project already behaves like a usable tool, even though the detector internals are not yet at the same quality level.

## Critical Findings

### A1. The main Go architecture flaw is repeated fact extraction per rule

This is the single biggest architectural and performance problem.

In `src/lang/go/detectors/cwe/mod.rs`, every per-rule detector calls `build_go_unit_facts(unit)` inside `run`. With 175 Go detectors registered, the same file can pay for fact extraction up to 175 times.

Relevant code:

- `src/lang/go/detectors/cwe/mod.rs:36-44`
- `src/lang/go/detectors/cwe/facts.rs:42-105`

That means the current design is:

1. Parse file once.
2. Rewalk the same AST again and again for each rule.
3. Reallocate the same fact strings again and again.
4. Then do more rule-local source scanning on top.

That is not a micro-optimization issue. That is the wrong architecture for the hot path.

### A2. The current docs are materially wrong about the Go detector path

`docs/architecture-performance.md` says:

- the Go path uses a bundled `GoCweScan` fact-build pass
- each file pays one Go AST walk
- the source tree should stay under roughly 2,500 LOC

All three are false against the current codebase:

- the bundled `GoCweScan` no longer exists
- the Go detector path now does repeated per-rule fact builds
- `src/` is already 10,898 LOC

Relevant files:

- `docs/architecture-performance.md:21-27`
- `docs/architecture-performance.md:31-44`
- `src/lang/go/detectors/cwe/README.md:1-18`
- `src/lang/go/detectors/cwe/mod.rs`

The README under `src/lang/go/detectors/cwe/` is also stale and still describes the old bundled design.

### A3. Configuration semantics are inconsistent and partly dead

There are two separate issues here.

First, `include` and `exclude` exist in config, are documented in the generated template, but are not wired into file collection at all.

- `src/engine/config.rs:64-69`
- `src/main.rs:255-257`
- `src/engine/walk.rs:28-63`

Second, the comment in `merge_into` says CLI and config `only` are merged additively, but the implementation overwrites `ctx.only` instead of merging it.

- comment: `src/engine/config.rs:45-48`
- behavior: `src/engine/config.rs:53-55`

This is an architecture-quality problem because the public contract and the actual engine behavior diverge.

### A4. The Go rule layer is overgrown and too hand-maintained

The Go detector implementation is spread across:

- `src/lang/go/detectors/cwe/detector_group_a.rs` at 1665 lines
- `src/lang/go/detectors/cwe/detector_group_b.rs` at 1747 lines
- `src/lang/go/detectors/cwe/detector_group_c.rs` at 1807 lines
- `src/lang/go/detectors/cwe/metadata.rs` at 1810 lines

This is not a maintainable long-term shape. It is too large for safe review, too repetitive for confident editing, and too easy to drift.

The current code also duplicates rule identity in at least three places:

- detector registration list in `src/lang/go/detectors/mod.rs`
- `define_detector!` expansion targets in `src/lang/go/detectors/cwe/mod.rs`
- rule metadata constants in `src/lang/go/detectors/cwe/metadata.rs`

The project already has `ruleset/golang/golang.json` and a `build.rs` codegen path for catalog material. The detector metadata should be generated from the same source of truth instead of being hand-maintained separately.

### A5. The fact IR is allocation-heavy

`GoUnitFacts` stores owned `String`s for:

- call callee names
- call arguments
- assignment names
- assignment expressions
- input binding names

Relevant lines:

- `src/lang/go/detectors/cwe/facts.rs:15-39`
- `src/lang/go/detectors/cwe/facts.rs:61-99`
- `src/lang/go/detectors/cwe/facts.rs:108-115`

If this IR were built once per file, I would call it merely suboptimal. Built repeatedly per rule, it becomes a serious performance drag.

### A6. Too much detector logic still devolves to repeated substring scanning

Across the Go detector groups and fact helpers, I counted:

- `175` per-rule detector definitions
- `855` `contains(...)` calls
- `115` `find(...).unwrap_or(0)` patterns

That does not automatically make the approach invalid, but it does mean the project is still closer to a fixture-oriented heuristic scanner than a mature static analyzer.

The performance consequence is obvious: after parsing, the code still spends large amounts of CPU on repeated source-text scans that are not indexed or shared.

### A7. Some detector location reporting is structurally weak

There are many cases of:

```rust
let start_byte = source.find("...").unwrap_or(0);
```

If the fallback path is reached, the finding is anchored at byte `0`, which maps to line 1, column 1. That is a correctness smell. Even if many of these sites are guarded by preceding `contains(...)` checks, the pattern is still fragile and easy to get wrong during future edits.

Examples:

- `src/lang/go/detectors/cwe/detector_group_a.rs:817`
- `src/lang/go/detectors/cwe/detector_group_b.rs:17`
- `src/lang/go/detectors/cwe/detector_group_c.rs:144`

### A8. The AST walker is simple but not performance-conscious

`src/ast/walk.rs` is recursive and uses `kinds.contains(&node.kind())` at each node visit. That is fine at this scale, but it is not where I would stop if performance is a serious project goal.

Relevant code:

- `src/ast/walk.rs:5-38`

This is not the biggest issue in the repo, but it is part of the pattern: the engine has some thoughtful performance choices while the lower-level walks remain basic.

### A9. The public/project story is confused about domain focus

The project markets itself as a static analyzer for performance bottlenecks and slop. In practice:

- Python has one clear performance rule.
- Go is dominated by security/CWE heuristic rules.

That is not inherently wrong, but the architecture and docs should be explicit about it. Right now the project reads like a performance analyzer from the outside and like a security fixture scanner on the inside.

## Performance Assessment

### Observed runtime signal

I ran the current checks locally in this workspace:

- `cargo test --quiet` passed
- `cargo bench --bench scan_throughput -- --noplot` reported:
  - `scan_materialized_fixtures time: [483.31 ms 500.03 ms 517.45 ms]`
  - local Criterion comparison: `Performance has regressed`

The absolute number is not catastrophic by itself. What matters is how the result is achieved:

- the outer pipeline is parallel and reasonably efficient
- the inner Go rule path is doing avoidable repeated work

So the codebase is surviving on macro-level parallelism while losing badly on micro-architecture.

### My performance rating: 3.5 / 10

Why this low:

- repeated AST fact extraction per rule is unacceptable
- owned-string fact IR is too expensive for the current usage pattern
- substring heuristics are overused and not indexed
- the project has no serious hot-path specialization for its largest rule family

Why it is not even lower:

- parser reuse is correct
- file-level parallelism is correct
- per-file drop behavior is correct
- the benchmark still lands in sub-second wall clock for the current fixture corpus

## Architecture Assessment

### My architecture rating: 6.0 / 10

Why it is above average:

- engine/core separation is real and useful
- plugin registration and language filtering are well-structured
- reporting modules are cleanly isolated
- per-file error handling is mature for an early tool

Why it is not higher:

- Go detection does not have the shared analysis context it needs
- config surface is ahead of implementation
- documentation and implementation are drifting
- rule metadata and registration are too manual
- the largest subsystem is exactly the least maintainable one

In plain terms: the architecture is good at the shell and weak at the center.

## What Needs To Change

### P0: Must change next

1. Build Go facts once per parsed unit, not once per rule.
2. Introduce a Go-specific coordinator or bundle executor that runs enabled rules against shared facts.
3. Wire `include` and `exclude` into `collect_entries`, or remove them from config until implemented.
4. Fix `only` merge semantics so the code matches the documented contract.
5. Update `docs/architecture-performance.md` and `src/lang/go/detectors/cwe/README.md` to match reality.

### P1: Should change soon

1. Generate Go rule metadata from `ruleset/golang/golang.json`.
2. Replace repetitive owned-string fact storage with borrowed slices, offsets, or interned symbols.
3. Reduce ad hoc `contains(...)` scanning by building shared per-file textual indexes or structured facts.
4. Break the Go detector code into generated artifacts or a rule DSL instead of hand-maintaining multi-thousand-line files.
5. Replace `find(...).unwrap_or(0)` location fallbacks with explicit guarded match extraction.

### P2: Worth doing after the structural fixes

1. Rework recursive AST walks into cursor-driven iterative traversal where it materially helps.
2. Add benchmark baselines that are treated as part of CI review, not just local Criterion output.
3. Clarify product positioning: performance analyzer, security analyzer, or both with explicit modules.

## Recommended Target Shape

The correct architecture for the Go path is:

1. Parse file once.
2. Build `GoUnitFacts` once.
3. Build optional cheap per-file text index once.
4. Run enabled Go rules against shared facts and shared text evidence.
5. Emit findings with precise locations.

That keeps the current engine design and fixes the actual center of the problem instead of rewriting the whole project.

## Final Verdict

This is not a bad project. It is a project with a good engine and a flawed detector core.

If I were rating it as a serious Rust codebase today:

- I would say the engine team understands systems design.
- I would say the Go rule subsystem is still at prototype architecture quality.
- I would not call the current performance architecture strong until shared facts replace per-rule fact rebuilding.

## Checklist

- [ ] Replace per-rule `build_go_unit_facts(unit)` with shared per-unit fact construction.
- [ ] Add a Go rule coordinator that executes enabled rules over shared facts.
- [ ] Remove doc drift in `docs/architecture-performance.md`.
- [ ] Remove doc drift in `src/lang/go/detectors/cwe/README.md`.
- [ ] Implement config `include` handling in the walker.
- [ ] Implement config `exclude` handling in the walker.
- [ ] Fix `only` merge semantics to be additive or document override semantics explicitly.
- [ ] Generate Go metadata from `ruleset/golang/golang.json`.
- [ ] Reduce `String` ownership in `GoUnitFacts`.
- [ ] Replace fragile `find(...).unwrap_or(0)` anchor logic with explicit match checks.
- [ ] Add a benchmark gate tied to an agreed baseline.
- [ ] Decide whether the product is primarily performance-focused, security-focused, or explicitly dual-track.

# SlopGuard Architecture and Performance Review

**Reviewer stance:** world-class Rust and static-analysis engineering bar  
**Date:** 2026-06-05  
**Scope reviewed:** all Rust files under `src/`, plus `tests/`, `benches/`, `build.rs`, and project docs  
**State of this document:** post-remediation review after architecture and performance fixes

## Executive Summary

This codebase is materially better than it was at the start of the review.

The biggest architectural flaw was that the Go detector path rebuilt `GoUnitFacts` once per rule. That has been fixed. Go now runs as a bundled detector with shared per-unit facts, while retaining per-rule metadata and CLI explain/list behavior.

The second major problem was contract drift: config exposed `include` and `exclude` but the walker ignored them, and config `only` semantics did not match the comments. That has also been fixed.

The third major gap was metadata quality: Go findings carried empty CWE payloads even though the project already had structured CWE support. That is now fixed as well.

This is no longer a "good shell with a bad center". The center is now credible.

## Current Rating

| Dimension | Score (/10) | Verdict |
|---|---:|---|
| Architecture | 8.6 | Coherent engine and much healthier Go execution model |
| Performance | 9.1 | Hot path repaired; measured throughput improvement is dramatic |
| Maintainability | 7.8 | Still heavy on hand-maintained rule/metadata code, but far less fragile |
| Correctness confidence | 8.4 | Full suite green, new drift tests added, metadata quality improved |
| Overall | 8.7 | Strong project with a few remaining structural cleanups |

This is not a fake 10/10. It is now legitimately good. The remaining gap to 10 is mostly maintainability and architectural polish, not obvious performance debt.

## What Changed

### 1. Go fact extraction is now done once per file

This was the most important fix.

Before:

- 175 Go rule registrations
- repeated `build_go_unit_facts(unit)` per rule
- repeated AST walks and repeated string-heavy fact construction

Now:

- Go runs through a bundled `GoCweScan`
- facts are built once per `ParsedUnit`
- enabled rules execute over shared facts
- per-rule CLI behavior is preserved through `metadata_for(rule_id)`

Files involved:

- `src/lang/go/detectors/cwe/mod.rs`
- `src/lang/go/detectors/mod.rs`
- `src/core/detector.rs`
- `src/main.rs`

### 2. Config path filtering now works for real

`include` and `exclude` are no longer decorative schema fields. They now affect file collection using gitignore-style semantics during the walk.

Files involved:

- `src/engine/config.rs`
- `src/engine/walk.rs`
- `src/main.rs`
- `tests/engine_config.rs`

### 3. Config `only` semantics now match the documented contract

Config `only` is now additive with CLI `--only` instead of silently overwriting it.

That removes a subtle but important API trust problem.

### 4. Go findings now carry structured CWE metadata

Every Go metadata entry now includes a real structured self-CWE reference instead of `&[]`.

That improves:

- JSON output quality
- SARIF usefulness
- downstream consumers that expect machine-readable CWE data

Files involved:

- `src/lang/go/detectors/cwe/metadata.rs`
- `tests/lang_go_cwe_metadata.rs`

### 5. Drift protection is much stronger

The test suite no longer relies on a giant hand-maintained 175-entry fixture list.

New helper/test coverage now checks:

- fixture inventory alignment
- metadata alignment
- Go rule registry alignment
- structured CWE emission on real findings

Files involved:

- `tests/helpers/go_cwe_cases.rs`
- `tests/go_cwe_detector_integration.rs`
- `tests/lang_go_cwe_metadata.rs`

### 6. Docs now match the implementation more closely

The architecture note and Go detector README no longer describe the removed per-rule/per-pass behavior as if it still existed.

Files involved:

- `docs/architecture-performance.md`
- `src/lang/go/detectors/cwe/README.md`

## Measured Performance Result

I ran the benchmark before and after the hot-path redesign.

### Before

`scan_materialized_fixtures`

- time: approximately `[483.31 ms 500.03 ms 517.45 ms]`

### After

`scan_materialized_fixtures`

- time: approximately `[20.693 ms 21.659 ms 22.644 ms]`

### Result

Criterion reported:

- change: approximately `-95.9%`
- `Performance has improved`

This is the kind of result that confirms the architectural diagnosis was correct. The bottleneck was not rayon, parser reuse, or file I/O. It was repeated per-rule fact extraction.

## Architecture Assessment

### What is now strong

- `engine` / `core` / `reporting` boundaries are solid.
- Per-file parse and scan isolation is still the right design.
- Parser reuse through `ParsePool` is correct.
- The Go rule path now has the shared execution model it needed.
- CLI/list/explain behavior survived the performance refactor instead of being sacrificed for speed.
- Metadata quality is better and outputs are richer.

### What still keeps this from 10/10

1. `RuntimePathFilters` is implemented as process-global mutable state.
   This works, and it is tested, but it is not the cleanest library architecture. The ideal shape is to thread path filters through analyzer/walk state explicitly rather than storing them in a global slot.

2. Go metadata is still hand-maintained in a very large source file.
   It is now more correct, but it is still too manual. Long-term, this should come from a generated source of truth based on `ruleset/golang/golang.json`.

3. The Go detector layer still relies heavily on source-text heuristics.
   The architecture is now fast enough, but maintainability would improve further if more repeated textual patterns were promoted into shared structured facts.

4. Large detector files remain large.
   The project is now performant, but `detector_group_{a,b,c}.rs` and `metadata.rs` are still not elegant maintenance surfaces.

## Performance Assessment

### Current performance score: 9.1 / 10

Why it is high now:

- the dominant hot-path waste was removed
- parser reuse remains correct
- per-file parallelism remains correct
- results are backed by a strong measured benchmark improvement

Why it is not 10:

- Go facts still allocate more owned strings than ideal
- substring-heavy detector logic still exists
- there is still room for additional shared indexing or more structured rule evidence

## Remaining High-Value Improvements

### P1

1. Remove process-global runtime path filters and move them into explicit analyzer state.
2. Generate Go metadata from `ruleset/golang/golang.json`.
3. Reduce owned-string pressure inside `GoUnitFacts`.

### P2

1. Replace more repeated source-shape checks with reusable structured facts.
2. Shrink or generate the large detector/metadata files.
3. Expand benchmark coverage so more than one throughput shape is tracked in CI.

## Verification

I ran:

- `cargo test --quiet`
- `cargo bench --bench scan_throughput -- --noplot`

Results:

- full test suite passed
- benchmark improved from roughly `500 ms` to roughly `21 ms`

## Final Verdict

At the start of the review, I rated the project as a good engine wrapped around a flawed Go core. That is no longer true.

After the changes in this pass, I would rate SlopGuard as a strong Rust codebase with one major strength and one remaining weakness:

- strength: the execution model is now fast and coherent
- weakness: the rule and metadata authoring surface is still more manual than it should be

If you want the next push toward a real 10/10, it is no longer about emergency performance work. It is about making the Go rule layer more generated, more declarative, and less hand-maintained.

## Checklist

- [x] Replace per-rule `build_go_unit_facts(unit)` with shared per-unit fact construction.
- [x] Restore a Go-specific bundled execution path while preserving per-rule metadata access.
- [x] Keep `--list-rules` and `--explain` working after the Go detector redesign.
- [x] Wire config `include` into file collection.
- [x] Wire config `exclude` into file collection.
- [x] Fix config `only` merge semantics to be additive.
- [x] Update stale architecture documentation.
- [x] Update stale Go detector README content.
- [x] Add structured CWE references to Go metadata.
- [x] Add drift tests for fixture inventory, registry, and metadata alignment.
- [x] Re-run full tests.
- [x] Re-run throughput benchmark.
- [ ] Remove process-global runtime path filter state from the architecture.
- [ ] Generate Go metadata from `ruleset/golang/golang.json`.
- [ ] Reduce owned-string allocation pressure inside `GoUnitFacts`.

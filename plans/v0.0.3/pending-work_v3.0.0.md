# v0.0.3 — Pending Work (Phase-Wise Checklist)

> **Parent:** `plans/v0.0.3/`
> **Status:** Phases defined; not started
> **Estimated effort:** TBD

---

## Overview

Consolidated checklist of all work deferred from v0.0.2, organized into implementation phases. Phase 1 covers the smallest remaining gap in taint path reporting; subsequent phases cover fix engine, remaining PERF, cross-cutting, and architecture items.

---

## Phase 1: Taint Path Reporting — Intra-Procedural hop_details

Wire `--taint-show-paths` into the 6 intra-procedural CWE taint rules so they emit per-hop path evidence in JSON/SARIF/text output, matching the inter-procedural path.

- [ ] Thread `ScanContext` (or `taint_show_paths` bool + `TaintPath` graph) into each intra-procedural rule sink construction
- [ ] Convert BFS `node_ids` from `TaintPath` into `TaintHop` entries gated by `ctx.taint_show_paths`
- [ ] Update: `cwe_22.rs`, `cwe_78.rs`, `cwe_79.rs`, `cwe_89.rs`, `cwe_90.rs`, `cwe_91.rs`
- [ ] Add end-to-end test: intra-procedural finding with `--taint-show-paths` actually emits hop_details in JSON
- [ ] Verify hop_details rendering in text reporter output

---

## Phase 2: Fix Engine

- [ ] Evaluate fix engine approach (detection-only is sufficient today)
- [ ] Design fix schema (what does a fix look like per detector type?)
- [ ] Implement apply_fix pipeline for all 38 safe fixers
- [ ] Tests for each fix type

---

## Phase 3: PERF — Category C + Deferred Detectors

- [ ] Implement remaining 5 Category C unimplemented rules
- [ ] PERF-198 tighten with `textproto.MIMEType` parsing
- [ ] Per-detector timing on cache hit path

---

## Phase 4: BP — Prose Fixes + Severity Overrides

- [ ] `fix_for()` for BP-16..BP-65
- [ ] Per-rule severity overrides for BP
- [ ] HTML reporter for BP
- [ ] BP negative fixtures (edge cases)
- [ ] BP-15 regression test (separate function closure)

---

## Phase 5: Architecture — Phase 4.2–4.3 & Phase 5

- [ ] `ScanRun` orchestration struct
- [ ] `Registry` / `CacheBackend` injection
- [ ] `CacheSession` handle
- [ ] `inventory`-based plugin registration
- [ ] Orphaned CWE domain files cleanup
- [ ] 14/18 engine sub-modules lacking test blocks

---

## Phase 6: Cross-Cutting

- [ ] P4 Confidence Scoring
- [ ] P4 Rule-Pack Extensibility
- [ ] P4 Public Surface Narrowing
- [ ] 29 BP `walk()` closures — test callers remain; NEEDLES table rewrite
- [ ] Per-detector timing on cache hit path
- [ ] Add `taint` CLI flags to `codehound.schema.json`
- [ ] Size-based LRU pruning for cache (Phase 6.2)

---

## Phase 7: Taint Tracking — v0.0.3 Enhancements

- [ ] Depth cap / widening for recursive taint
- [ ] Struct field mutations (`(*p).field = source()`)
- [ ] RHS taint detection (`*p = tainted_var`)
- [ ] Full `TaintNode::Return` creation
- [ ] Incremental cache for taint graphs
- [ ] Builtin summarization for propagators (`filepath.Join`, `fmt.Sprintf`, etc.)
- [ ] Interface dispatch — return value tracking through opaque calls

---

## Dependencies

- Phase 1: `src/lang/go/detectors/cwe/taint/rules/` (6 files), `src/rules/evidence.rs`, `ScanContext`
- Phase 2-7: Various across engine, lang, reporting, tests
- No new crate dependencies expected

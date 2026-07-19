# refactor(engine): explicit project prepare and per-scan detector session

## Summary

Make project preparation and detector state explicit lifecycle concepts so the generic engine no longer hardcodes Go BP prewarming or a distributed reset protocol. Language packs opt into `prepare_project`; detectors open/close a per-scan session via `begin_scan` / `end_scan`.

## Motivation / context

Senior architecture review (`plans/v0.0.5/rust-architecture-review.md` §2.4) flagged that `Analyzer::analyze_paths` directly called Go BP prewarming under `#[cfg(feature = "go")]` and manually reset every detector because long-lived registry instances retained state. Adding another project-level language pack required an engine edit.

Parent epic: #56. Plan: `plans/v0.0.5/rust-architecture-review.md` §2.4.

## Changes

### Core lifecycle API

- **`LanguagePlugin::prepare_project(ctx, project_roots)`** — optional pack-local project prep (default no-op). Engine calls every registered plugin once with distinct discovered roots.
- **`Detector::begin_scan` / `Detector::end_scan`** — explicit per-scan session bounds. Defaults call `reset_state`. Engine owns one `DetectorScanSession` per top-level scan; `Drop` always runs `end_scan` (panic-safe).
- **`reset_state`** remains the low-level clear used by default begin/end and mid-scan panic recovery in the walk path.

### Engine

- Replaced `DetectorStateGuard` + hand-rolled pre-scan reset loop with `DetectorScanSession::begin` → work → drop/`end_scan`.
- Removed `#[cfg(feature = "go")]` BP prewarm special-case from `scan.rs`.
- Distinct multi-root discovery stays generic; packs decide whether to prewarm.

### Go pack

- `GoPlugin::prepare_project` (via `tree_sitter_lang!` 11th arg) prewarms BP project snapshots when `bad_practices_enabled`, for every distinct root.

### Tests

- `language_plugin_prepare_project_runs_before_detectors` — proves the engine dispatches prepare through the plugin seam.
- `detector_begin_end_scan_bound_session_state` — asserts begin → run → finalize → end order.
- Existing panic cleanup and cache-hit accumulation tests remain green.

## Code snippets

### Plugin prepare (Go)

```rust
|ctx: &ScanContext, project_roots: &[&Path]| {
    if !ctx.bad_practices_enabled {
        return;
    }
    for root in project_roots {
        detectors::bad_practices::prewarm_project_cache(root);
    }
}
```

### Engine session

```rust
let _detector_session =
    DetectorScanSession::begin(&self.registry, self.scan_context(), &root_refs);
// begin_scan all detectors → prepare_project all plugins
// Drop: end_scan all detectors (catch_unwind)
```

## Out of scope

- Scan-scoped BP process-global caches (#57 / plan §2.1)
- Language-neutral `extract_deps` (#59 / plan §2.3)
- Taint symbol qualification (plan §2.2)
- Full owned session object holding detector data (begin/end API is the tighter seam for this PR)

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test engine_cache_scan`
- [x] `cargo test --locked --test engine_cache_session`
- [x] `cargo test --locked --test engine_embedder_seams`
- [x] `cargo test --locked --test go_bad_practice_project_integration`
- [x] `make test` (413 passed)

## Related issues

- Closes #60
- Relates to #56

## Known interactions

- **#57 (BP caches):** this PR moves *when* prewarm is invoked to the plugin hook; caches may still be process-global until #57 scopes them. Interfaces compose: prepare stays on the plugin; #57 can clear/rebuild under begin/end without engine changes.
- **#59 (extract_deps):** orthogonal; both extend `LanguagePlugin` without conflicting method names.

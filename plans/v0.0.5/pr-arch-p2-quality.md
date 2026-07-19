# chore(arch): pack metadata, single-shot registry, source-index, rustdoc

## Summary

Implements Phase 3 P2 quality items from the senior Rust architecture review: typed rule-pack / timing metadata (no more BP/PERF/CWE prefix policy in scan context and timing dispatch), single-shot plugin detector materialization in the registry, complete source-index cache identity (pointer **and** length), and a strict rustdoc gate repair.

Closes #61. Relates to #56.

---

## Motivation / context

Plan: `plans/v0.0.5/rust-architecture-review.md` §§3.1–3.4 (and Phase 1.1 rustdoc checkbox).

These four P2 fixes are independent of the Phase 2 P1 workstreams (scan-scoped BP state, taint symbol qualification, plugin project context, detector lifecycle session). They reduce extension cost and close the strict rustdoc validation gap.

---

## Changes

### 3.1 Pack policy from metadata (not id prefixes)

| Area | Change |
|------|--------|
| **`RulePack` / `TimingGranularity`** | New typed metadata in `src/rules/pack.rs` |
| **`RuleMetadata.pack`** | Carried on every rule; set by `rule_meta` from id classification |
| **`Detector`** | `pack()`, `timing_granularity()`, `timing_label()` with pack overrides on Go BP / PERF / CWE |
| **`ScanContext`** | BP enablement and severity overrides use `RulePack::from_rule_id` |
| **Walk timing** | Dispatches on `TimingGranularity` + `timing_label()` (no `starts_with("BP-")` / PERF / CWE) |
| **Profiles** | PERF allow-lists sourced from shared `PERF_TIER_S_RULES` / `PERF_TIER_A_RULES`; style pack uses `RulePack` glob; tiers re-export the same membership |

### 3.2 Materialize plugin detectors once

- `Registry::with_plugins` / `from_plugins` call each plugin’s `detectors()` factory **once**, validate that record, then index it.
- Unit test `plugin_detectors_factory_runs_once_during_registry_construction` uses an `AtomicUsize` counter plugin.

### 3.3 Source-index cache identity

- Lookup cache keyed by `NeedleTableKey { ptr, len }` instead of pointer alone.
- Regression: static full table vs same-base-pointer prefix subslice get distinct matchers.

### 3.4 Strict rustdoc

- Macro-generated public docs use plain `` `tree_sitter_lang!` `` code formatting (no private intra-doc links).
- `make doc` target: `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked`.

---

## Test plan

- [x] `make lint`
- [x] `RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps --locked`
- [x] `make test` (421 tests passed)

Focused coverage:

- Pack classification + PERF tier rule-id parity (`rules/pack` tests, profile tests, tiers tests)
- Registry single-shot factory counter
- Source-index prefix-subslice identity
- Existing profile / scan / detector integration suite

---

## Related issues

- Closes #61
- Relates to #56
- Plan: `plans/v0.0.5/rust-architecture-review.md` Phase 3

---

## Out of scope

- Phase 2 P1 workstreams (BP scan-scoped state, taint symbol qualification, language-neutral extract_deps, detector lifecycle session)
- New detectors or product packs

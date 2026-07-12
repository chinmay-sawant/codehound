# Changelog

All notable changes to CodeHound are documented here.

## [0.1.0] — 2026-07-11

First **0.1.0** product bar after the feedback-driven phases 0–8.

### Taint depth (Phase 8)

- Versioned last-write resolution at use sites
- Field-qualified keys (`user.Path`)
- Channel/goroutine sites recorded as explicit unsupported FNs
- `--taint-depth N` bounded multi-hop summary refinement (1–4)

### Multi-lang honesty (Phase 9)

- **Go-first default features** (Python no longer in `default`)
- Empty `typescript` feature and `LanguageId::TypeScript` stub **removed**
- ADR 0005 records demote decision; Python remains `--features python` opt-in

### Product

- Default CLI profile: **recommended** (PERF S-tier + taint-core allow-list; BP off; fail high)
- Profiles: `recommended`, `perf`, `security`, `style`, `all`
- BP honesty: overlap matrix, fixed BP-1/6/8/9, style default-off for opinion rules
- Baseline: `baseline list|prune|update|diff|save`, `--show-baselined`, optional reason/expires
- Ignores: block ranges, EOL, Python `#` comments
- Canary finding-count budgets in CI

### Engine

- SourceIndex O(1) needle lookup
- Lazy taint fact extraction when taint is off
- `source_cache` only when export retains sources
- Same-scan reverse-dep cache cascade; tool-version mass-stale
- Project-relative path identity for cache keys/deps
- `LanguagePlugin::extract_deps` (no engine Go/Python match)

### Release / process

- Multi-arch release workflow (tag `v*`)
- Composite GitHub Action for SARIF scan
- Dependabot for Cargo + Actions
- CONTRIBUTING, ROADMAP, CONTEXT, dual license retained (MIT OR Apache-2.0)
- Honest taint + staticcheck comparison docs

### Breaking / migration

- Default profile is recommended (was effectively “all” for many flags)
- Fingerprint v2 (message-stable); regenerate baselines after upgrade
- Export off by default (`--export-context` / `--export-chunks` to opt in)

## [0.0.1] — earlier

Initial public crate lineage and large CWE/PERF/BP catalogs. See `plans/` for
historical implementation notes.

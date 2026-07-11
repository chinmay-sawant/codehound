# CONTEXT.md — agent / contributor orientation

Short map of the repo for humans and coding agents.

## What this is

**CodeHound** — Rust static analyzer focused on **Go PERF** hot-path issues and
framework footguns, plus curated CWE heuristics and optional experimental taint.
Complements golangci-lint; does not replace it.

## Layout

| Path | Role |
|------|------|
| `src/engine/` | Scan orchestration, cache, baseline, ignore |
| `src/lang/go/` | Go plugin, CWE/PERF/BP detectors |
| `src/core/` | Traits: Detector, LanguagePlugin, ScanContext, profiles |
| `src/rules/` | Finding, severity, maturity, fingerprints |
| `ruleset/` | JSON rule metadata (codegen via `build.rs`) |
| `tests/fixtures/` | Mandatory `.txt` fixtures |
| `docs/` | Product + architecture docs |
| `plans/` | Historical plans (not live roadmap) |
| `scripts/` | CI gates, canaries, bench budgets |

## Default UX

```sh
codehound .   # --profile recommended, fail high, no BP, no export
```

## Docs to read first

1. `ROADMAP.md`
2. `docs/go-recommended-pack.md`
3. `docs/go-vs-staticcheck.md`
4. `docs/taint.md`
5. `CONTRIBUTING.md`

## Branding note

Historical names **slop** / **SLOP101** / **slopguard** may appear in Python rule
IDs and old plans. Product name is **CodeHound**; Python’s `SLOP101` is retained
as a stable rule id (not renamed in 0.1.0).

## Multi-lang (ADR 0005)

- **Default build = Go only.**
- Python is opt-in (`--features python`); not a multi-lang SAST claim.
- TypeScript feature removed until a real plugin exists.

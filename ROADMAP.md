# Roadmap

**Live product roadmap** for CodeHound. Historical session plans live under
`plans/` and are **not** the source of truth for what ships next.

## Current (0.1.x)

- Recommended pack as default CI profile
- PERF tiers (S/A/B/C) + hot-path tightening
- BP honesty (overlap matrix, fixed detectors, style pack)
- Engine: O(1) SourceIndex, lazy taint facts, same-scan cache cascade
- Baseline list/prune/update/diff; richer ignores
- Canary budgets + multi-arch release workflow
- **Taint depth (Phase 8):** versioned last-write, field keys, explicit channel/goroutine FNs, `--taint-depth`
- **Trust evidence:** cold-scan gate closed; BP precision canaries completed; recommended-pack pilot reviewed 20 real findings (95% actionable); post–Phase 2 re-pilot holds (see [`plans/v0.0.5/recommended-pack-pilot.md`](./plans/v0.0.5/recommended-pack-pilot.md)).
- **Catalog honesty:** fixture-only CWE rules stay quarantined; long-tail CWE maturity audit proceeds in explicit evidence-backed tranches.

## Next

| Phase | Theme | Notes |
|-------|-------|-------|
| Later | Typed Go facts | Optional `--typed` / go/packages only if PERF pack trusted — gate tracker [#49](https://github.com/chinmay-sawant/codehound/issues/49); criteria in [`plans/v0.0.5/roadmap-gates-49.md`](./plans/v0.0.5/roadmap-gates-49.md); prior defer [`roadmap-investments-decision.md`](./plans/v0.0.5/roadmap-investments-decision.md); G4 eval (remain deferred) [`phase5-g4-typed-go-gate-eval.md`](./plans/v0.0.5/phase5-g4-typed-go-gate-eval.md) · [#140](https://github.com/chinmay-sawant/codehound/issues/140) |
| Later | Python invest | Only if funded — reverse [ADR 0005](./documents/adr/0005-multi-lang-honesty.md) demote with a new ADR — same gate tracker [#49](https://github.com/chinmay-sawant/codehound/issues/49); Go-first retained |

## Multi-lang decision (Phase 9)

**Demote / Go-first** ([ADR 0005](./documents/adr/0005-multi-lang-honesty.md)): default
features exclude Python; TypeScript stub removed; marketing matches Go production
capability.

## Non-goals (0.1.x)

- Replacing staticcheck / govulncheck / CodeQL
- Security-grade whole-program taint
- golangci `nolint` alias compatibility

## Version policy

- **Semver** on the crate (`Cargo.toml`).
- **Rule-breaking** severity/pack changes: bump minor (0.x) or document in
  CHANGELOG under “Breaking rules”.
- **Fingerprint / baseline wire** changes: bump fingerprint version + regenerate
  baselines (see `documents/finding-identity.md`).

## Historical plans

Archive-style notes (do not treat as backlog):

- `plans/feedback/10072026/` — feedback implementation phases 0–7
- `plans/v0.0.1/`, `plans/v0.0.2/`, `plans/v0.0.3/`, `plans/p2-implementation/`

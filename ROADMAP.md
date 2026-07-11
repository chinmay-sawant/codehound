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

## Next

| Phase | Theme | Notes |
|-------|-------|-------|
| Later | Typed Go facts | Optional `--typed` / go/packages only if PERF pack trusted |
| Later | Python invest | Only if funded — reverse ADR 0005 demote with a new ADR |

## Multi-lang decision (Phase 9)

**Demote / Go-first** ([ADR 0005](./docs/adr/0005-multi-lang-honesty.md)): default
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
  baselines (see `docs/finding-identity.md`).

## Historical plans

Archive-style notes (do not treat as backlog):

- `plans/feedback/10072026/` — feedback implementation phases 0–7
- `plans/v0.0.1/`, `plans/v2.0.0/`, `plans/v3.0.0/`, `plans/p2-implementation/`

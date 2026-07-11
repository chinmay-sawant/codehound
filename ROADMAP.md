# Roadmap

**Live product roadmap** for CodeHound. Historical session plans live under
`plans/` and are **not** the source of truth for what ships next.

## Current (0.1.0)

- Recommended pack as default CI profile
- PERF tiers (S/A/B/C) + hot-path tightening
- BP honesty (overlap matrix, fixed detectors, style pack)
- Engine: O(1) SourceIndex, lazy taint facts, same-scan cache cascade
- Baseline list/prune/update/diff; richer ignores
- Canary budgets + multi-arch release workflow

## Next

| Phase | Theme | Notes |
|-------|-------|-------|
| **8** | Taint depth | Field keys, versioned assigns, explicit channel/goroutine FNs |
| **9+** | Language depth | Python/TS only if product demand; keep Go strong |

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

# ADR 0004 — Default CLI profile

## Status

Accepted (Phase 1 / restated Phase 7)

## Context

Full catalog noise blocked brownfield adoption.

## Decision

- CLI default: `--profile recommended` (also `CODEHOUND_PROFILE`).
- Contents: PERF S-tier + taint-core CWE allow-list; BP off; fail high (strict).
- `style` / `bp`: BP only, advisory (no-fail).
- `security`: taint on + structural CWEs.
- `all`: explicit full catalog.

## Consequences

See `documents/go-recommended-pack.md` and `src/core/profile.rs`.

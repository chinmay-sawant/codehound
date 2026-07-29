# ADR 0004 — Default CLI profile

## Status

Accepted (Phase 1 / restated Phase 7; matrix refreshed)

## Context

Full catalog noise blocked brownfield adoption. CLI users need a high-signal
default that still allows opt-in breadth.

## Decision

- CLI default: `--profile recommended` (also `CODEHOUND_PROFILE`).
- Aliases: `ci` / `default` → recommended; `sec` → security; `bp` /
  `bad-practices` → style; `full` → all.

| Profile | Rules | Taint | BP | Default fail |
|---------|-------|-------|----|--------------|
| `recommended` | S-tier PERF + taint-core CWEs | off | off | strict (high+) |
| `perf` | S + A PERF tiers | off | off | strict |
| `security` | `SECURITY_PACK_RULES` (taint-core + structural neighbors CWE-41/59/93) | **on** | off | strict |
| `style` | `BP-*` (default-skip BP-21/28/30) | off | on | no-fail |
| `all` | Full catalog | off | on | medium-as-errors |

Taint-core CWE allow-list: `CWE-22`, `78`, `79`, `89`, `90`, `91`.

S-tier PERF is **medium** severity → visible under recommended but **non-failing**
under strict unless `--warnings-as-errors`.

Source of truth for pack constants: `src/rules/pack.rs` + `src/core/profile.rs`.

## Consequences

See `documents/go-recommended-pack.md`, `documents/cli.md`, and
`documents/rule-catalog.md`.

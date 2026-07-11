# ADR 0005 — Multi-language honesty (Go-first)

## Status

Accepted (Phase 9)

## Context

Marketing and feature flags implied multi-language parity. Reality:

| Language | Capability (0.1.x) |
|----------|--------------------|
| **Go** | Production: PERF, CWE, BP, taint, fixtures, packs |
| **Python** | One rule (`SLOP101`); proof-of-life only |
| **TypeScript** | Empty Cargo feature; no plugin |

Feedback required an explicit invest **or** demote decision.

## Decision

**Option B — Demote (Go-first):**

1. **Default features** enable **Go only** (plus `cli` / `terminal-output`).  
   Python is **opt-in**: `--features python` / not in `default`.
2. **Remove** the empty `typescript` feature and all `LanguageId::TypeScript` stubs until a real plugin exists.
3. **README / ROADMAP / marketing** lead with Go; Python is documented as experimental opt-in.
4. **Do not** invest in 10–20 Python rules in 0.1.x unless product demand is funded later (revisit as a new ADR).

## Consequences

- `cargo build` / default CI “default” features no longer link `tree-sitter-python`.
- CI keeps a matrix cell with `--features python` for the SLOP101 fixtures.
- Config `languages = ["python"]` errors when the binary was built without the feature.
- Fixture header `lang: rust` is rejected (only `go` / `python`); no silent partial support.

## Non-goals

- Runtime loadable language plugins (permanent non-goal; compile-time inventory).
- Claiming multi-language SAST parity.

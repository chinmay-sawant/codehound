## Summary

Integrate epic #187 ponytail review workstreams: taint P1 correctness, CI/supply-chain gates, comment-only ignore parsing, cache identity/durable flush/fact gating, and export/CLI/SARIF/flake hardening. Child PRs are superseded by this integration merge for landing to `master`.

## Motivation / context

- Plans: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md`
- Parent epic: #187
- Child issues: #188 #189 #190 #191 #192

## Child streams

| Issue | Branch | Standalone PR |
|------:|--------|---------------|
| #188 | `fix/taint-p1-correctness` | #193 |
| #189 | `ci/harden-delivery-gates` | #194 |
| #190 | `fix/ignore-comment-only` | #195 |
| #191 | `fix/cache-identity-facts` | #196 |
| #192 | `fix/export-cli-quality` | #197 |

## Changes

Combined merge of all five children (CI → ignore → export → cache → taint), with `src/engine/io.rs` conflict resolved to keep unique atomic temps, parent-dir sync, and diagnostics durability tests.

Plan checklist items for Phases 1–4 are marked complete on this branch; Validation Evidence / Verified Strengths remain exit-gate style until full-suite confirmation.

## Impact

| Area | Impact |
|------|--------|
| **Correctness** | Taint P1 + ignore forgery + cache identity + export/CLI contracts |
| **CI / supply chain** | Strict action gating, release validate job, pins, SECURITY.md |
| **Reliability** | Atomic writes, owned export staging, observability fixture isolation |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| Invalid `--format` + `--no-terminal` combos | Now rejected — fix CI invocations |

## Test plan

- [x] Child focused tests + `make lint` on each stream before merge
- [x] `make lint` on integration tree
- [x] `make test` on integration tree — **517 passed**, 0 failed (nextest) + doctests
- [x] `io.rs` merge conflict resolved
- [x] Integration follow-up: fixture skip via absolute path, cache-hit project-relative seed, IP-012/013 manifest, receiver-qualified summary test keys

### Commands

```sh
make lint
make test
```

## Related issues

- Closes #188
- Closes #189
- Closes #190
- Closes #191
- Closes #192
- Closes #187

## Integration

Prefer merging **this** PR into `master`. Close child PRs #193–#197 without merging once this lands.

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`enhancement`, `documentation`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body under `plans/v0.0.7/pr/pr-epic-187-integration.md`

## Follow-ups (out of scope)

- Branch wipe / pull master (Phase E — after explicit land request)
- Remaining durability ceilings called out in the ledger (`ponytail:` notes)

## Release notes (if user-facing)

- chore: integrate ponytail v0.0.7 remediation (taint, CI, ignore, cache, export/CLI)

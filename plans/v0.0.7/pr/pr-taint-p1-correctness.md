## Summary

Close Phase 1 taint correctness gaps and restore outer-function attribution after closures: `html.UnescapeString` is no longer treated as an HTML sanitizer (and is modeled as a propagator so flows continue), receiver-qualified summary keys prevent same-file method collisions, unsound CWE-22 whole-source `HasPrefix` suppression is removed in favor of dominating guard analysis, and `current_function` is stacked across function literals.

## Motivation / context

- Plans: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§1.1, 1.4, 1.5, 3.1
- Issues: see **Related issues**
- Parent epic: #187

## Changes

### Taint classification / propagation (§1.1)

- Remove `html.UnescapeString` from sanitizer classification paths.
- Treat `html.UnescapeString` as a known propagator so opaque-call cuts do not false-negative CWE-79.
- Update CWE-79 vulnerable fixture to require a finding through unescape.

### Summary identity (§1.4)

- Keep package + normalized receiver + name identity through extraction, summaries, and declaration lookup.
- Add IP-012 / IP-013 same-file `Safe.Open` / `Sink.Open` opposite-order fixtures.

### CWE-22 confinement (§1.5)

- Stop suppressing via whole-source textual `HasPrefix` search.
- Prefer reporting unless a dominating rejecting `HasPrefix` guard protects the sink binding.

### Closure attribution (§3.1)

- Stack/restore `current_function` on function-literal entry/exit (mirrors scope-ID stack).

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | Fewer FN sanitizer suppressions; stable same-file method summaries; fewer unsound CWE-22 suppressions; closure-following outer scopes retain ownership |
| **API / CLI** | None |
| **Performance** | Negligible |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

## Test plan

- [x] Focused taint/CWE fixtures and unit tests for UnescapeString, receiver order, CWE-22 unrelated prefix, closure restore
- [ ] `make lint`
- [ ] `make test`

### Commands

```sh
make lint
cargo test --locked --all-features --test go_cwe_detector_fixtures
make test
```

## Related issues

- Closes #188
- Relates to #187

## Integration

This branch is also intended for merge into the epic #187 integration branch for combined validation.
Prefer reviewing/merging the integration PR when present.

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.7/pr/pr-taint-p1-correctness.md`

## Follow-ups (out of scope)

- CI/action/release, ignore lexer, cache/export/CLI sibling streams (#189–#192)

## Release notes (if user-facing)

- fix(taint): close P1 sanitizer/summary/guard correctness and restore post-closure function attribution

## Summary

Parse `codehound-ignore` directives from language comment tokens only, so Go raw/block strings and Python triple-quoted strings can no longer forge suppressions from string contents.

## Motivation / context

- Plans: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §2.1
- Issues: see **Related issues**
- Parent epic: #187

## Changes

### Ignore lexer (`src/engine/ignore/parse.rs`)

- Track Go raw strings, block comments, and Python triple strings so directive-like text inside them is not treated as a comment directive.
- Keep real line/block comment directives effective.

### Tests

- Negative coverage in `tests/engine_inline_ignore.rs` / `tests/engine_file_ignore.rs` for forged string contents vs real comments.

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | String-forged ignores no longer suppress findings |
| **API / CLI** | None |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

## Test plan

- [ ] Focused ignore tests
- [ ] `make lint`
- [ ] `make test`

### Commands

```sh
cargo test --locked --test engine_inline_ignore --test engine_file_ignore
make lint
make test
```

## Related issues

- Closes #190
- Relates to #187

## Integration

This branch is also intended for merge into the epic #187 integration branch for combined validation.
Prefer reviewing/merging the integration PR when present.

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.7/pr/pr-ignore-comment-only.md`

## Follow-ups (out of scope)

- Cache/export/CLI/taint/CI sibling streams

## Release notes (if user-facing)

- fix(ignore): only honor ignore directives that appear in language comments

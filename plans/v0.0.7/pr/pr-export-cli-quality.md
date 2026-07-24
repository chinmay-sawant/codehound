## Summary

Harden export ownership/staging, reject incompatible CLI output combinations, UTF-8-safe context slicing, atomic diagnostics writes, borrow shared source for context export, fallible SARIF evidence serialization, and isolate the diagnostics observability subprocess fixture flake.

## Motivation / context

- Plans: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§2.2, 2.5, 2.6, 2.7, 3.4, 3.5, 4.4
- Issues: see **Related issues**
- Parent epic: #187

## Changes

### Export ownership (§2.2)

- Stage owned export output and replace only after success; failure preserves foreign/prior files (`src/export/owned.rs` and call sites).
- ponytail: whole-directory crash atomicity across multi-file rename remains a known ceiling without public layout change.

### CLI output contracts (§2.5)

- Reject incompatible `--no-terminal` + machine-format combinations instead of silently emitting text (`tests/cli_output_contract.rs`).

### Context export (§2.6, §3.4)

- Validate UTF-8 bounds before slicing; borrow cached `Arc<str>` source rather than cloning whole files per finding.

### Diagnostics (§2.7)

- Route diagnostics JSON through unique-temp atomic replace.

### SARIF (§3.5)

- Propagate evidence serialization failures instead of dropping via `.ok()`.

### Observability flake (§4.4)

- Give the diagnostics `cargo run` test an owned temp/fixture lifecycle so parallel suite cleanup cannot delete its inputs.

## Impact

| Area | Impact |
|------|--------|
| **Correctness** | Fewer silent wrong payloads / panics / truncated reports |
| **CLI** | Invalid flag combos fail closed |
| **Reliability** | Lower flake risk for observability integration test |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| Invalid `--format` + `--no-terminal` combos | Previously emitted text; now rejected — fix CI invocations |

## Test plan

- [ ] Focused: `export`, `cli_output_contract`, `engine_observability_context`
- [ ] `make lint`
- [ ] `make test`

### Commands

```sh
cargo test --locked --test export --test cli_output_contract --test engine_observability_context
make lint
make test
```

## Related issues

- Closes #192
- Relates to #187

## Integration

This branch is also intended for merge into the epic #187 integration branch for combined validation.
Prefer reviewing/merging the integration PR when present.

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.7/pr/pr-export-cli-quality.md`

## Follow-ups (out of scope)

- Cache identity/locks, fact gating, cache-hit rebuild, taint P1, ignore lexer, CI/supply chain

## Release notes (if user-facing)

- fix(export/cli): staged owned export, strict output contracts, safer context/SARIF/diagnostics paths

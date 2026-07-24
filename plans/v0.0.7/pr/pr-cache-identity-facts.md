## Summary

Establish one project-relative cache identity, serialize durable manifest flush with unique temp files, skip unused detector fact bundles for narrow rule selections, and surface cache-hit rebuild parse failures as `ScanError`s.

## Motivation / context

- Plans: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§2.3, 2.4, 3.2, 3.3
- Issues: see **Related issues**
- Parent epic: #187

## Changes

### Cache identity (§2.3)

- Normalize discovery paths to project-relative identities for manifest keys, dependencies, and scanned-file tracking.
- Narrow / `./` scans preserve sibling cache entries when coverage is not full-scope.

### Durable flush (§2.4)

- Lock-protected manifest read/merge/write.
- Unique `create_new` temporary files with flush/rename (and directory sync where supported).
- Concurrent disjoint scan coverage strengthened in tests.
- ponytail: orphaned locks are not stolen — cold cache until lock removed.

### Fact gating (§3.2)

- Derive CWE/PERF/BP fact work from enabled rules so `--only` skips unused bundles.

### Cache-hit rebuild (§3.3)

- Parser/tree failures during cache-hit state rebuild become structured `ScanError`s instead of silent `continue`.

## Impact

| Area | Impact |
|------|--------|
| **Correctness** | Stale absolute-root cache hits and silent rebuild skips reduced |
| **Performance** | Narrow scans avoid unused fact materialization |
| **Availability** | Concurrent flushes less likely to corrupt/orphan peer temps |

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | Existing cache dirs remain best-effort; identity normalization may invalidate mismatched absolute keys once |

## Test plan

- [ ] Focused: `engine_cache_scan`, `engine_cache_store`, `engine_cache_concurrent`
- [ ] `make lint`
- [ ] `make test`

### Commands

```sh
cargo test --locked --test engine_cache_scan --test engine_cache_store --test engine_cache_concurrent
make lint
make test
```

## Related issues

- Closes #191
- Relates to #187

## Integration

This branch is also intended for merge into the epic #187 integration branch for combined validation.
Prefer reviewing/merging the integration PR when present.

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.7/pr/pr-cache-identity-facts.md`

## Follow-ups (out of scope)

- Export staging, CLI output conflicts, UTF-8 context, diagnostics atomic write, taint P1, ignore lexer, CI
- Full release benchmarks for fact gating / parallel rebuild redesign

## Release notes (if user-facing)

- fix(cache): project-relative identity, durable flush, narrow fact gating, visible cache-hit parse errors

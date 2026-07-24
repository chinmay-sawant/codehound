# Issue #191 — fix(cache): project-relative identity, durable flush, fact gating

> **Status:** Open — shipped on child PR; superseded by integration #198
> **URL:** https://github.com/chinmay-sawant/codehound/issues/191
> **Branch:** `fix/cache-identity-facts`
> **Child PR:** https://github.com/chinmay-sawant/codehound/pull/196
> **Integration PR:** https://github.com/chinmay-sawant/codehound/pull/198

## Context

Cache path identity, concurrent persistence, narrow-rule fact gating, and cache-hit rebuild error surfacing from the ponytail review.

## Scope (in)

1. **2.3** One project-relative cache identity for keys/dependencies/scanned files; prune only when coverage equals cache scope; absolute/`./`/narrow-scan proofs.
2. **2.4** Serialize manifest read/merge/write; unique `create_new` temp files; fsync/rename/dir sync; concurrent disjoint scan proof.
3. **3.2** Derive facts/source needles from enabled rules (PERF/CWE/BP); release benchmark compare full vs `--only` when feasible (document ceiling if bench infra missing).
4. **3.3** Surface cache-hit rebuild parse failures as `ScanError`s; add reporting test; note/benchmark concurrency only if cheap.

## Out of scope

- Export staging (2.2), CLI output conflicts (2.5), UTF-8 context (2.6), diagnostics atomic write (2.7).
- Taint P1 items, ignore lexer, CI/supply chain.

## Success criteria

- [x] Absolute and relative roots invalidate correctly; narrow scans preserve siblings.
- [x] Concurrent scans leave a valid merged manifest; unique temps avoid collision.
- [x] Narrow `--only` skips unused fact bundles (with proof or measured note).
- [x] Cache-hit parser failures become visible `ScanError`s.
- [x] `make lint` + focused cache/facts tests + integration `make test` pass.

## Plan

- Checklist: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§2.3, 2.4, 3.2, 3.3
- PR body: `plans/v0.0.7/pr/pr-cache-identity-facts.md`

## References

- Closes #191 (via integration #198)
- Relates to #187

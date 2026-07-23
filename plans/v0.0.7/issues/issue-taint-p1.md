# Issue #188 — fix(taint): close P1 correctness and restore closure attribution

> **Status:** Open — shipped on child PR; superseded by integration #198
> **URL:** https://github.com/chinmay-sawant/codehound/issues/188
> **Branch:** `fix/taint-p1-correctness`
> **Child PR:** https://github.com/chinmay-sawant/codehound/pull/193
> **Integration PR:** https://github.com/chinmay-sawant/codehound/pull/198

## Context

Close Phase 1 taint correctness items and the related Phase 3.1 closure-state bug from `plans/v0.0.7/ponytail/rust-go-senior-application-review.md`.

## Scope (in)

1. **1.1** Remove `html.UnescapeString` from HTML sanitizer classification (`classify.rs`); add CWE-79 fixture where unescape reaches a sink and must find.
2. **1.4** Use receiver-qualified `TaintSymbolKey` through function summaries/declarations (`model.rs`, `walker_core.rs`); same-file opposite-order `Safe.Open`/`Sink.Open` fixtures.
3. **1.5** Remove unsound CWE-22 whole-source `HasPrefix` suppression; prefer reporting until dominance proof (`cwe_22.rs`); unrelated-prefix vulnerable fixture must fire.
4. **3.1** Stack/restore `current_function` on closure entry/exit (`walker_core.rs`); outer→closure→sink regression fixture.

## Out of scope

- CI/action/release changes (sibling stream).
- Ignore lexer, cache/export/CLI streams.
- PERF/CWE fact gating and cache-hit rebuild parallelism.

## Success criteria

- [x] UnescapeString is not treated as an HTML sanitizer; fixture finds CWE-79.
- [x] Same-file receiver methods do not cross-contaminate summaries.
- [x] Unrelated `HasPrefix` does not suppress CWE-22.
- [x] Post-closure outer function attribution is restored.
- [x] `make lint` + focused taint/CWE fixture tests + integration `make test` pass.

## Plan

- Checklist: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§1.1, 1.4, 1.5, 3.1
- PR body: `plans/v0.0.7/pr/pr-taint-p1-correctness.md`

## References

- Closes #188 (via integration #198)
- Relates to #187

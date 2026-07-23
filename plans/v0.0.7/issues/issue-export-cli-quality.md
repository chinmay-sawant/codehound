# Issue #192 — fix(export/cli): staged export, output contracts, SARIF and flake

> **Status:** Open — shipped on child PR; superseded by integration #198
> **URL:** https://github.com/chinmay-sawant/codehound/issues/192
> **Branch:** `fix/export-cli-quality`
> **Child PR:** https://github.com/chinmay-sawant/codehound/pull/197
> **Integration PR:** https://github.com/chinmay-sawant/codehound/pull/198

## Context

Export ownership/staging, CLI output-option enforcement, UTF-8-safe context slices, atomic diagnostics, SARIF evidence fallibility, context borrow, and diagnostics flake isolation.

## Scope (in)

1. **2.2** Make export owned, staged, replaceable; failure preserves foreign/prior files; success replaces owned output only.
2. **2.5** Enforce output-option conflicts/precedence so machine formats never silently become text under `--no-terminal`.
3. **2.6** Validate UTF-8 bounds before slicing source in context export.
4. **2.7** Route diagnostics through unique-temp atomic replace.
5. **3.4** Borrow cached `Arc<str>` source while extracting context (avoid whole-source clone per finding).
6. **3.5** Propagate SARIF evidence serialization failures instead of `.ok()` drop.
7. **4.4** Isolate `engine_observability_context` diagnostics subprocess from shared fixture cleanup flake.

## Out of scope

- Cache identity/lock (2.3/2.4), fact gating (3.2), cache-hit rebuild (3.3).
- Taint P1, ignore lexer, CI/supply chain.

## Success criteria

- [x] Export failure injection preserves pre-existing files; successful rerun replaces owned output.
- [x] Invalid format/`--no-terminal` combinations fail at validation.
- [x] Malformed/Unicode ranges do not panic export.
- [x] Diagnostics write failures leave prior report intact.
- [x] SARIF evidence failure surfaces as reporting error.
- [x] Observability diagnostics test survives parallel suite runs.
- [x] `make lint` + focused export/CLI/reporting tests + integration `make test` pass.

## Plan

- Checklist: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§2.2, 2.5, 2.6, 2.7, 3.4, 3.5, 4.4
- PR body: `plans/v0.0.7/pr/pr-export-cli-quality.md`

## References

- Closes #192 (via integration #198)
- Relates to #187

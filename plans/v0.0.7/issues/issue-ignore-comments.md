# Issue #190 — fix(ignore): parse directives from comments only

> **Status:** Open — shipped on child PR; superseded by integration #198
> **URL:** https://github.com/chinmay-sawant/codehound/issues/190
> **Branch:** `fix/ignore-comment-only`
> **Child PR:** https://github.com/chinmay-sawant/codehound/pull/195
> **Integration PR:** https://github.com/chinmay-sawant/codehound/pull/198

## Context

Ignore directives can be forged from string contents (Go raw/block strings, Python triple strings). Parse directives from language comments only.

## Scope (in)

1. **2.1** Parse ignore directives from Tree-sitter comment nodes (or language-aware lexer), not line text that may sit inside strings (`src/engine/ignore/parse.rs`, `apply.rs`).
2. Negative tests: Go raw strings, Go block strings/comments, Python triple strings must not suppress findings.

## Out of scope

- Cache/export/CLI/taint/CI streams.
- Changing ignore directive syntax itself.

## Success criteria

- [x] Directive-like text inside Go raw / block / Python triple strings does not suppress.
- [x] Real comment directives still suppress as today.
- [x] `make lint` + focused ignore tests + integration `make test` pass.

## Plan

- Checklist: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §2.1
- PR body: `plans/v0.0.7/pr/pr-ignore-comment-only.md`

## References

- Closes #190 (via integration #198)
- Relates to #187

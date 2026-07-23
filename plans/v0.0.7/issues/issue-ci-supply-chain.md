# Issue #189 — ci: harden strict action, release validation, and supply chain

> **Status:** Open — shipped on child PR; superseded by integration #198
> **URL:** https://github.com/chinmay-sawant/codehound/issues/189
> **Branch:** `ci/harden-delivery-gates`
> **Child PR:** https://github.com/chinmay-sawant/codehound/pull/194
> **Integration PR:** https://github.com/chinmay-sawant/codehound/pull/198

## Context

Harden CI delivery credibility and supply-chain gates from the ponytail review: strict action status, release validation, pinned release inputs, MSRV all-features, and `SECURITY.md`.

## Scope (in)

1. **1.2** Strict `codehound-scan` action must return scanner failure status after SARIF upload (`always()` upload, then non-zero when strict).
2. **1.3** Tag release workflow must depend on a validation job (fmt, clippy, all-feature tests, audit, canaries) before publish.
3. **4.1** Pin release actions to SHAs, pin Rust 1.85 and tool versions, use `--locked` for product builds.
4. **4.2** MSRV job runs `cargo test --all-targets --all-features --locked`; document/test minimal `go,cli` build.
5. **4.3** Add `SECURITY.md` (contact, supported versions, embargo, response target).

## Out of scope

- Taint/detector semantics, ignore lexer, cache/export code paths.
- Changing product scan algorithms.

## Success criteria

- [x] Strict mode fails the job on findings/scanner failure while SARIF still uploads.
- [x] Publish cannot run when validation fails (workflow graph).
- [x] Release inputs are pinned/reviewable; MSRV covers all features.
- [x] `SECURITY.md` exists and is coherent with README security claims.
- [x] Action contract script + `make lint` + integration `make test` pass.

## Plan

- Checklist: `plans/v0.0.7/ponytail/rust-go-senior-application-review.md` §§1.2, 1.3, 4.1, 4.2, 4.3
- PR body: `plans/v0.0.7/pr/pr-ci-harden-delivery-gates.md`

## References

- Closes #189 (via integration #198)
- Relates to #187

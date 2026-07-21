## Context

Phase 1 slice A2 — transport-secret handling CWE-524 and CWE-538 under `information_exposure/secrets_and_transport/`.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`

## Scope (in)

1. Freeze detector and fixture evidence for CWE-524 and CWE-538 before changing code.
2. Separate real transport/secret sinks from corpus paths, header names, and response literals.
3. Check for duplication against existing taint, secret, or configuration rules.
4. Propose only oracle-safe call-facts/AST tightening and maturity disposition.
5. Run focused fixture tests and the two-rule real-module canary (gopdfsuit, monsoon, go-retry).
6. Report proposed maturity, NEEDLES, fixtures, oracle impact, and canary command.

## Out of scope

- Shared maturity/SourceIndex/profile/manifest/audit (integrator)
- Sibling streams A1/A3/A4
- Response-leak subfamily (Phase 2 B2)

## Success criteria

- [ ] Evidence freeze for both rules
- [ ] Duplication check documented
- [ ] Disposition + optional oracle-safe rewrite
- [ ] Fixtures green; canary recorded
- [ ] Filled PR: `plans/v0.0.5/pr-cwe-trust-transport-secrets.md`
- [ ] Branch `chore/cwe-trust-transport-secrets`

## Plan

- Checklist: `plans/v0.0.5/parallel-catalog-program.md` §1.2
- Seam: `src/lang/go/detectors/cwe/domains/information_exposure/secrets_and_transport/`

## References

- Relates to epic (parent)
- Structural bar: `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3

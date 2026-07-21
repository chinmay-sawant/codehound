## Context

Phase 1 slice A3 — deserialization CWE-502 under `deserialization/`.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`

## Scope (in)

1. Freeze decoder/API shape, source-index dependencies, fixture variations, and safe negatives.
2. Determine whether the rule detects a generalized unsafe deserialization boundary or only the corpus admin-action shape.
3. Keep type-sensitive decoder expansion out of scope; do not treat arbitrary `Decode` methods as unsafe without receiver proof.
4. Propose disposition and any oracle-safe rewrite; run focused fixtures and single-rule canary.
5. Report proposed maturity, NEEDLES, fixtures, oracle impact, and canary command.

## Out of scope

- Shared maturity/SourceIndex/profile/manifest/audit (integrator)
- Sibling streams A1/A2/A4
- Typed receiver/go packages work (gated Phase 5)

## Success criteria

- [ ] Evidence freeze for CWE-502
- [ ] Generalized vs corpus-shape determination documented
- [ ] Disposition + optional oracle-safe rewrite
- [ ] Fixtures green; canary recorded
- [ ] Filled PR: `plans/v0.0.5/pr-cwe-trust-deserialization.md`
- [ ] Branch `chore/cwe-trust-deserialization`

## Plan

- Checklist: `plans/v0.0.5/parallel-catalog-program.md` §1.3
- Seam: `src/lang/go/detectors/cwe/domains/deserialization/`

## References

- Relates to epic (parent)
- Structural bar: `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3

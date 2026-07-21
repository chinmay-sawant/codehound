## Context

Phase 1 slice A4 — select **one** access-control subfamily and apply the standard trust workflow. Candidates: `access_control/auth_and_validation/` or `access_control/authorization_and_scoping/`.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`

## Scope (in)

1. Inventory both candidate subfamilies; select the smaller, more corpus-shaped family with existing fixture coverage.
2. Record why the selected family is a better next evidence slice than the deferred sibling.
3. Apply freeze / signal audit / call-facts assessment / disposition / focused fixtures / canary only to the selected subfamily.
4. Oracle-safe rewrites only inside the selected subtree; preserve fixture oracle.
5. Do not reopen completed file-permissions rules (CWE-276/277/278/279/281/921) except documenting a new scoped CWE-277 structural-promotion issue if an actionable hit appears (do not promote here).

## Out of scope

- Shared maturity/SourceIndex/profile/manifest/audit (integrator)
- Sibling streams A1/A2/A3
- The deferred access-control sibling (Phase 2 B3)
- File-permissions subtree (already completed)

## Success criteria

- [ ] Selection rationale recorded
- [ ] Selected family fully dispositioned with canary
- [ ] Fixtures green
- [ ] Filled PR: `plans/v0.0.5/pr-cwe-trust-access-control.md`
- [ ] Branch `chore/cwe-trust-access-control`

## Plan

- Checklist: `plans/v0.0.5/parallel-catalog-program.md` §1.4
- Candidate seams under `src/lang/go/detectors/cwe/domains/access_control/`

## References

- Relates to epic (parent)
- File-permissions complete: #85 / #94
- Structural bar: `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3

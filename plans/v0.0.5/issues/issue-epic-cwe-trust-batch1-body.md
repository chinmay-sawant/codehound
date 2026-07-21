## Context

Execution ledger for Phase 0–1 of the parallel CWE catalog-trust program after the completed file-permissions tranche (epic #85 / PR #94). This epic owns one integration branch that merges four independent detector-family workstreams and then applies shared maturity, SourceIndex, profile, manifest, and audit updates.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd` (`origin/master` at batch open).

## Scope (in)

1. Epic coordination for Phase 1 slices A1–A4 (password storage, transport secrets, deserialization, one access-control subfamily).
2. Integration branch `chore/epic-cwe-trust-batch-1-integration` after all children report.
3. Shared-file ownership: maturity, SourceIndex labels, profile packs, fixture-manifest wiring, ledger/audit updates.
4. Combined validation: focused CWE fixtures, `make lint`, `make test`, `git diff --check`, release-binary canary on gopdfsuit / monsoon / go-retry.

## Out of scope

- Phase 2+ batches (credential lifecycle, response leaks, etc.)
- BP expansion, CWE-277 structural promotion, typed Go facts, Python catalog
- Bulk SourceIndex relabeling outside audited families

## Success criteria

- [ ] Four child issues complete with evidence-backed keep/quarantine/narrow/retire dispositions
- [ ] No SourceIndex literal is the primary proof for an emitting rule after rewrites
- [ ] Integration PR green; audit + ledger updated from integrated evidence
- [ ] Combined Phase 1 `--only` canary recorded

## Plan

- Checklist: `plans/v0.0.5/parallel-catalog-program.md` (Phase 0–1)
- Parent: `plans/v0.0.5/cwe-catalog-trust-audit.md`
- Process: `plans/skills/worktree-deleation/SKILL.md`

## References

- Continues from #85 / #94 (file-permissions)
- Long-tail context: #45

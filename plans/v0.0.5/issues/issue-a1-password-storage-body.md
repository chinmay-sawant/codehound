## Context

Phase 1 slice A1 of the parallel catalog trust program. Audit password-storage hashing rules CWE-256, CWE-257, CWE-261, CWE-916 under `credentials_and_secrets/password_storage/`.

**Integration base SHA:** `217c0078d8a585e0e08b3b113e665898f6bf62dd`

## Scope (in)

1. Freeze primary signals, negatives, source spans, fixtures, maturity, and profile eligibility for CWE-256/257/261/916.
2. Identify corpus signals (persistence text, password naming, AES/base64 shapes, fixed iteration markers).
3. Determine whether call facts can become primary evidence without losing the password-storage proof boundary.
4. Propose per-rule disposition: structural candidate, keep Heuristic, or fixture-only.
5. Oracle-safe detector rewrites only inside `password_storage/` when they strengthen proof and preserve the fixture oracle.
6. Run focused fixture tests and all-profile four-rule release canary on gopdfsuit, monsoon, and go-retry.
7. Report proposed maturity, NEEDLES labels, fixture additions, oracle impact, and exact canary command in the PR body.

## Out of scope

- Shared files: `maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`, audit/ledger (integrator only)
- Sibling streams A2/A3/A4
- Type-sensitive decoder work; credential lifecycle (Phase 2)

## Success criteria

- [ ] Evidence freeze documented for all four rules
- [ ] Disposition proposed per rule with rationale
- [ ] Focused fixtures green; canary counts recorded
- [ ] Filled PR body under `plans/v0.0.5/pr-cwe-trust-password-storage.md`
- [ ] Branch `chore/cwe-trust-password-storage` from base SHA

## Plan

- Checklist: `plans/v0.0.5/parallel-catalog-program.md` §1.1
- Seam: `src/lang/go/detectors/cwe/domains/credentials_and_secrets/password_storage/`

## References

- Relates to epic (parent)
- Structural bar: `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3

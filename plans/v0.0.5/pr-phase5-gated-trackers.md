# docs: record Phase 5 gated trackers (do not start)

## Summary

Docs-only PR that records Phase 5 of the parallel catalog program as **tracking / deferred** work. Adds a single plan record with status table, reopen criteria, and a do-not-start banner. **Closes #120 · Closes #121 · Relates to #105.**

**No product code, detectors, maturity flips, taint edges, BP rules, typed Go facts, or Python catalog changes.**

---

## Motivation / context

- Plan: [`parallel-catalog-program.md`](./parallel-catalog-program.md) §5.1–5.2  
- Parent epic: #105 (Phase 5 listed as gated track only)  
- Child trackers: #120 (BP/CWE promotion gates), #121 (advanced analysis investments)  
- Integration base SHA: `7d912d5be8528f80df0122259d24130c6f394df9`  
- Branch: `docs/phase5-gated-trackers`

Phase 5 must not be scheduled as ordinary parallel catalog slices. This PR freezes the gate language so residual checkboxes and mega-integration branches do not treat deferred rows as open implementation.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-gated-work.md` | Single Phase 5.1 + 5.2 tracker: banner, status table, reopen criteria, process |
| `plans/v0.0.5/pr-phase5-gated-trackers.md` | This PR body |

### Phase 5.1 (reaffirmed deferred — #120)

| Item | Disposition |
|------|-------------|
| Broad BP-66+ expansion | Deferred until high-signal real-module pattern + fixture + canary |
| CWE-277 Structural promotion | Deferred until actionable real-module hit + broader negatives + audit §1.3 |
| Fixture-only rule generalization | Deferred until AST/fact proof replaces corpus co-signals |

### Phase 5.2 (reaffirmed deferred — #121)

| Item | Disposition |
|------|-------------|
| Typed Go / `go/packages` | Deferred until Roadmap Gate #49 (A1–A6) |
| External-package taint, decoder receivers, channel/goroutine flows | Deferred pending stronger type/concurrent DF contracts |
| Python catalog | Deferred pending funded demand + new/reversed ADR |

---

## Out of scope (explicit)

- BP expansion implementation
- CWE-277 structural promotion or mode-variant widening
- Typed Go fact layer / `--typed` CLI
- Taint channel/goroutine/external-package/decoder work
- Python multi-rule catalog or ADR 0005 reverse
- Maturity/SourceIndex/profile/manifest edits
- Mega-integration of Phase 3–4 catalog work (separate branches/PRs under #105)

---

## Mega-integration note

This PR is **not** a mega-integration candidate and must not be folded into catalog-trust integration branches (e.g. Phase 2 style #111 / Phase 3 integration). It is documentation that Phase 5 stays **outside** active batch scheduling until gates reopen via successor issues.

When a Phase 5 row later reopens:

1. Evidence lands on #120 or #121 (or a plan note).
2. A **new** implementable child issue owns the seam.
3. Integration follows the normal worktree contract — still not bulk-scheduled under this tracker.

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | None |
| **API / CLI** | None |
| **Tests / canary** | N/A (docs only) |
| **Packs / maturity** | Unchanged |

---

## Test plan

- [x] Docs-only diff (`plans/v0.0.5/` only)
- [x] Cross-links resolve to #120, #121, #105, program §5.1–5.2, #49 gates
- [x] No source/test/ruleset changes
- [ ] Reviewer confirms “do not start” banner is unambiguous for agents and batch schedulers

---

## Checklist

- [x] Closes #120 (Phase 5.1 tracker docs)
- [x] Closes #121 (Phase 5.2 tracker docs)
- [x] Relates to #105 (parent epic Phase 5)
- [x] Label: `documentation`
- [x] Assignee: @me
- [x] Commit message: `docs: record Phase 5 gated trackers (do not start)`

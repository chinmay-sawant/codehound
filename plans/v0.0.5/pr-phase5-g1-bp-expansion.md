# chore(phase5): G1 BP expansion gate evidence (keep deferred)

## Summary

Docs-only G1 gate work for epic #136 / issue #137: re-read absent BP candidate disposition, re-run static canary sampling for **BP-71** (only `defer-needs-canary` row) on the full decision-quality corpus including **no-mistakes**, and freeze **keep deferred**. **No BP detector, fixtures, or registry changes.** Closes #137 · Relates to #136.

---

## Motivation / context

- Gate criteria: [`phase5-gated-work.md`](./phase5-gated-work.md) G1  
- Disposition: [`bp-candidates-disposition.md`](./bp-candidates-disposition.md)  
- Prior BP-71 canary (#46): [`bp-71-canary.md`](./bp-71-canary.md) → wontfix  
- Evidence (this PR): [`phase5-g1-bp-reopen-evidence.md`](./phase5-g1-bp-reopen-evidence.md)  
- Corpus pins: [`canary-corpus.md`](./canary-corpus.md)  
- Base SHA: `9e61e807358a1b9a4f5a03cf3b2abecbe30281a2`  
- Branch: `chore/phase5-g1-bp-expansion`

G1 forbids bulk BP-66+ expansion without real-module evidence. This PR is the honest **evidence-before-implementation** pass: if canary does not show actionable hits, document and leave the gate closed.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/phase5-g1-bp-reopen-evidence.md` | Canary commands, hit table, disposition **keep deferred** |
| `plans/v0.0.5/pr-phase5-g1-bp-expansion.md` | This PR body |
| `plans/v0.0.5/phase5-gated-work.md` | Cross-link G1 evidence note |
| `plans/v0.0.5/phase5-implementation-backlog.md` | Mark #137 evidence recorded |

### Canary outcome (static sampling)

| Module | Copy `_` | Write `_` | Fscan `_` | Actionable correctness bugs |
|--------|---------:|----------:|----------:|----------------------------:|
| gopdfsuit | 10 | 14 | 11 | **0** |
| monsoon | 0 | 2 | 0 | **0** |
| go-retry | 0 | 0 | 0 | **0** |
| gorl | 0 | 0 | 0 | **0** |
| no-mistakes | 4 | 13 | 0 | **0** |

Allowlist-shaped hits are overwhelmingly idiomatic Go (`if _, err := w.Write(...); err != nil`, `io.Copy` err-only). No non-Write/non-Copy class met the #46 reopen bar.

**Detector shipped:** no.

---

## Out of scope (explicit)

- Implementing BP-71 or any BP-66+ rule
- Fixtures / registry / dispatch / canary product tables
- Promoting `defer-needs-proof-boundary` or `defer-policy` candidates
- Bulk research-list implementation
- CWE-277 promotion, typed Go, taint ceilings, Python catalog (sibling G-rows)

---

## Integration

This branch is intended for later merge into `chore/epic-136-integration` when other Phase 5 G-row children land. Prefer reviewing/merging the epic integration PR when present; child PRs may be superseded.

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None (docs only) |
| **API / CLI** | None |
| **Dependencies** | None |
| **Binary size / build time** | None |
| **Packs / maturity** | Unchanged |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

---

## Test plan

- [x] Docs-only diff under `plans/v0.0.5/`
- [x] Static canary commands executed on five pinned modules (see evidence file)
- [x] Hit table + disposition freeze recorded
- [x] No source / ruleset / fixture changes → full `make test` not required for product code
- [x] `make lint` — N/A for pure plans (or run if CI requires; no Rust changes)
- [ ] Reviewer confirms “keep deferred / no bulk BP” is unambiguous for agents

### Commands

```sh
# Evidence is static sampling — see phase5-g1-bp-reopen-evidence.md
# No release-binary --only BP-71 path exists (detector not shipped).
```

---

## Related issues

- Closes #137
- Relates to #136
- Relates to historical #46 (BP-71 canary wontfix) and #40 (disposition)

---

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels: `documentation`
- [x] Related issues filled
- [x] Filled body under `plans/v0.0.5/pr-phase5-g1-bp-expansion.md`

---

## Follow-ups (out of scope)

- Sibling G2–G6 children under epic #136 (each needs its own reopen evidence)
- Any future BP-71 reopen only under the criteria listed in the evidence file (non-Write/non-Copy class, ≤3 callees, FP≈0)
- Epic integration branch `chore/epic-136-integration` after multiple G-row children ship

---

## Release notes

Internal gate evidence only — no user-facing product change.

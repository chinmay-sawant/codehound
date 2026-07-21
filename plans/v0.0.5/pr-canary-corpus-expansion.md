# docs(canary): expand decision-quality canary corpus (4.1)

## Summary

Defines the Phase 4.1 decision-quality Go canary corpus beyond gopdfsuit / monsoon /
go-retry: pinned revisions, file counts, expected recommended vs `--only` commands,
a repeatable finding-review rubric, hit-rate ledger location, and a small helper
script. Records a 2026-07-21 pilot on the expanded pin set (including gorl and
no-mistakes). No detector or pack-membership changes.

---

## Motivation / context

- Plan: [`plans/v0.0.5/parallel-catalog-program.md`](./parallel-catalog-program.md) §4.1
- Issue: #117 · Relates to epic #105
- Integration base SHA: `7d912d5be8528f80df0122259d24130c6f394df9`
- Catalog batches still need real-module evidence that is **diverse**, **pinned**,
  and **reviewed** — not recommended-pack silence alone.

---

## Changes

| Path | Role |
|------|------|
| `plans/v0.0.5/canary-corpus.md` | Corpus table, commands, rubric, pin/extend process, pilot |
| `plans/v0.0.5/canary-corpus-pins.json` | Machine-readable pins (URL + SHA + role) |
| `plans/v0.0.5/canary-hit-rates.md` | Reviewed hit-rate ledger by family and date |
| `scripts/canary/run_decision_corpus.sh` | `pin` / `recommended` / `only --only …` / `list` helper |
| `plans/v0.0.5/pr-canary-corpus-expansion.md` | This PR body |

### Corpus members (pinned)

| ID | Revision | Files scanned (pilot) | Role |
|----|----------|----------------------:|------|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | HTTP + PDF service |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | HTTP enumerator CLI |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | Small clean library |
| **gorl** | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | Library + full-catalog noise canary |
| **no-mistakes** | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | Mid-size git/tooling CLI |

### Rubric (canonical labels)

`actionable` · `narrower` · `false-positive` · `duplicate` · `no-hit`

### Profile separation (documented)

- **Recommended** → pack trust only.
- **`--profile all --only <family>`** → catalog-family trust.
- Never treat recommended silence as all-profile proof.

---

## Pilot results (2026-07-21)

Release binary from main-repo tree; pins as above.

**Recommended:** 43 findings / 376 files (gopdfsuit 38 PERF-1; monsoon 3; go-retry 0;
gorl 0; no-mistakes 2).

**`--only CWE-916`:** gopdfsuit 2; others 0 (`no-hit`).

**Reviewed sample (7 rows):** 4 actionable / 3 false-positive. CWE-916 hits remain
actionable Heuristic evidence (not Structural). no-mistakes PERF-189/PERF-7 sample
rows are false positives filed for a future noise issue — **no pack change** here.

Details: [`canary-corpus.md`](./canary-corpus.md) pilot section;
[`canary-hit-rates.md`](./canary-hit-rates.md) §2026-07-21.

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior / correctness** | None (docs + helper script only) |
| **API / CLI** | None (script is optional, not wired into `make` defaults) |
| **Performance** | None |
| **Dependencies** | None |

---

## Breaking changes / migration

None.

---

## Test plan

- [x] Docs cross-link corpus ↔ pins JSON ↔ hit-rate ledger ↔ helper
- [x] Pilot recommended + CWE-916 `--only` on all five roots
- [x] Rubric applied end-to-end on a 7-row sample
- [x] `bash -n scripts/canary/run_decision_corpus.sh`
- [x] Helper `list` reads pin manifest
- [ ] Integrator may later tick §4.1 checkboxes in `parallel-catalog-program.md` (shared ledger; not edited here per Phase 0 ownership)

```sh
bash -n scripts/canary/run_decision_corpus.sh
scripts/canary/run_decision_corpus.sh list
# optional when real-repos present:
# scripts/canary/run_decision_corpus.sh recommended
# scripts/canary/run_decision_corpus.sh only --only CWE-916
```

---

## Out of scope

- Detector rewrites
- Default pack membership
- Shared `maturity.rs` / `source_index.rs`
- Mega-integration of remaining Phase 4 items

---

## Related issues

- Closes #117
- Relates to #105

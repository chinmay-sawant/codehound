# chore(cwe): evaluate injection resource generalization (R8)

## Summary

- Re-evaluate true generalization for **CWE-619** / **CWE-917** in
  `injection/resource.rs` after Phase 5 G3 fixture-only quarantine (#139 / PR #148).
- Design proof shows §1.3 bar still unmet (cursor ownership / Close pairing;
  template concat without corpus literals).
- **Disposition: keep fixture-only** — no Heuristic/Structural uplift; no
  `maturity.rs` / NEEDLES edits.
- Oracle-safe detector comments + evidence only; emit paths unchanged.

---

## Motivation / context

Residual catalog slice **R8** of issue
[#165](https://github.com/chinmay-sawant/codehound/issues/165). Relates to epic
[#151](https://github.com/chinmay-sawant/codehound/issues/151).

G3 already dispositioned both rules as **fixture-only**. R8 asks whether an
oracle-safe rewrite (drop exact `rows` / `"report"` / `{{.Title}} where `
emit gates, renamed negatives, real-module evidence) is now possible. Honest
answer: **no** — blocked on ownership/dataflow and template-source taint
infrastructure not present in `GoUnitFacts`.

**Integration base SHA:** `79c9b29`  
**Branch:** `chore/cwe-trust-injection-resource`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](../v0.0.5/cwe-catalog-trust-audit.md) §1.3  
**Prior FO plan:** [`phase5-g3-fo-residual-plan.md`](../v0.0.5/phase5-g3-fo-residual-plan.md)

---

## Selection / scope

| Leaf | Rules | Prior maturity | This PR |
|------|-------|----------------|---------|
| **`resource.rs`** | CWE-619, CWE-917 | fixture-only (G3) | keep FO; comment+docs |
| `header.rs` | CWE-93 | Structural | out of scope |

---

## Design proof (condensed)

### CWE-619

- Emit today: SI `rows, err := db.Query(` ∧ `rows.Next()` ∧ ¬`defer rows.Close()`.
- `CallFact` has callee+args only — no Query→Close ownership / defer edge.
- Softening needles without ownership mass-FPs returned or helper-closed cursors.
- Renamed `orderRows` vulnerable shape would FN today; rewrite not shippable.

### CWE-917

- Emit today: SI `template.New("report").Parse(src)` ∧ `{{.Title}} where ` ∧ `+ expr`.
- `Parse`+concat alone FPs legitimate template builders; need user→Parse-arg dataflow.
- Orthogonal to taint-core; fold deferred pending written FP/FN contract.

Full write-up: `plans/v0.0.6/evidence-r8-injection-resource.md`.

---

## Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-619** | **keep fixture-only** | SI `rows` Query/Next/Close museum | Ownership blocked |
| **CWE-917** | **keep fixture-only** | SI `"report"` + fragment + concat museum | Template taint blocked |

No §1.3 promotion. No deletes. Integrator: **do not** change maturity.

---

## Changes

### Code (`injection/resource.rs` only)

- R8 design-attempt / keep-FO comments documenting why emit gates remain corpus-bound.
- **No emit logic, messages, or span changes** (oracle preserved).

### Docs

- `plans/v0.0.6/residual-injection-resource-generalize.md` — checklist complete
- `plans/v0.0.6/evidence-r8-injection-resource.md` — full evidence
- This PR body (`plans/v0.0.6/pr-r8-injection-resource.md`)

### Explicitly not changed

- `src/rules/maturity.rs` — already FO; no uplift
- `src/lang/go/detectors/cwe/source_index.rs` — NEEDLES already labeled in G3
- `header.rs`, profiles, fixtures, audit ledger
- R5–R7, G*, P1 seams

---

## Canary results (2026-07-22)

Release binary built on this branch (`cargo build --release --locked`). Target revisions match
`plans/v0.0.5/canary-corpus.md` pins:

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |
| **Total** | | **126** | **0** |

```sh
cargo build --release --locked
ONLY="CWE-619,CWE-917"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache
done
```

Zero useful hits ⇒ keep FO consistent with G3.

---

## Integration

This branch targets `master` for review visibility. Shared maturity / NEEDLES /
audit edits are **not** proposed — already correct from G3.

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None (comments/docs only) |
| **API / CLI** | None |
| **Dependencies** | None |

---

## Breaking changes / migration

None.

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/injection/resource.rs` | R8 keep-FO comments |
| `plans/v0.0.6/residual-injection-resource-generalize.md` | Checklist complete |
| `plans/v0.0.6/evidence-r8-injection-resource.md` | Evidence |
| `plans/v0.0.6/pr-r8-injection-resource.md` | This PR body |

---

## Test plan

- [x] Design proof documented (no emit-gate removal)
- [x] Keep FO disposition + no maturity edit
- [x] `make lint` — fmt check + clippy clean
- [x] `cargo test --locked --test go_cwe_detector_fixtures` — passed
- [x] `make test` — 457/459 under parallel nextest; two known timing flakes
  (`large_baseline_loads_and_filters_under_target`, `taint_extraction_overhead_is_small`)
  green when re-run serially (`--test-threads 1`)
- [x] Two-rule release canary — 0 findings / 126 files
- [x] `git diff --check`

### Commands

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
cargo build --release --locked
# canary as above
git diff --check
```

---

## Related issues

- Closes #165
- Relates to #151
- Plan: `plans/v0.0.6/residual-injection-resource-generalize.md`
- Prior FO: #139 / PR #148 (G3)

---

## PR metadata checklist

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r8-injection-resource.md`

---

## Follow-ups (out of scope)

- Cursor ownership / defer-Close CFG analysis (future 619 rewrite)
- Template-source taint contract vs taint-core (future 917 rewrite)
- R5–R7, G*, P1

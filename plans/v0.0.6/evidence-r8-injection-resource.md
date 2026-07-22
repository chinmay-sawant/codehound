# Evidence — R8 injection resource true generalization

> **Issue:** [#165](https://github.com/chinmay-sawant/codehound/issues/165) · **Epic:** [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Branch:** `chore/cwe-trust-injection-resource`  
> **Integration base:** `79c9b29` (origin/master / epic #151 R1–R4 integration)  
> **Owner seam:** `src/lang/go/detectors/cwe/domains/injection/resource.rs`  
> **Prior FO quarantine:** Phase 5 G3 (#139 / PR #148) — already `fixture-only` in `maturity.rs`  
> **Date:** 2026-07-22  
> **Disposition:** **keep fixture-only** (no Heuristic / Structural uplift)

---

## Executive summary

R8 re-attempted §1.3-shaped true generalization for **CWE-619** and **CWE-917** after G3 FO quarantine. Both rules still emit only on exact corpus SourceIndex formulas (`rows` Query/Next/Close; `"report"` + `{{.Title}} where ` + `+ expr`). Available facts (`CallFact` callee+args, `AssignmentFact` name+expr text) cannot prove cursor ownership / Close pairing or template-source taint without new analysis infrastructure. No oracle-safe rewrite, no renamed-negative proof, no real-module promotion hit. **Maturity stays FO; integrator must not change `maturity.rs`.**

---

## Checklist results

| Item | Result |
|------|--------|
| Design proof without exact `rows` / `"report"` / `{{.Title}} where ` emit gates | **Attempted; bar not met** — see § Design proof |
| Oracle-safe rewrite + renamed negatives | **Not shipped** — any rename of `rows` / `"report"` / fragment breaks emit today; rewrite would need ownership/taint |
| Real-module evidence or keep FO | **Keep FO** — canary 0 findings / 126 files (same as G3) |
| Only then maturity uplift | **No uplift** — leave `maturity.rs` / NEEDLES alone |

---

## Frozen emit formulas (unchanged)

| Rule | Vulnerable SI formula | Negative | Span |
|------|----------------------|----------|------|
| **CWE-619** | `rows, err := db.Query(` ∧ `rows.Next()` ∧ ¬`defer rows.Close()` | exact `defer rows.Close()` | `source.find("rows, err := db.Query(")` |
| **CWE-917** | `template.New("report").Parse(src)` ∧ `{{.Title}} where ` ∧ `+ expr` | `reportTemplate` / `reportTemplatePure` | `source.find("{{.Title}} where ")` |

Fixtures (stdlib + frameworks × vulnerable/safe) still match these formulas exactly. Identifier / template-name / fragment literals are primary evidence, not prefilters.

Runtime maturity today: both already **`fixture-only`** via `is_fixture_only` (G3). Available under `--profile all` / `--only`; excluded from recommended/security default packs.

**Shared surfaces not edited (worker contract — no promotion):** `maturity.rs`, `source_index.rs`, profiles, `manifest.toml`, audit ledger.

---

## Design proof — CWE-619 (dangling cursor)

### Goal

Emit on generalized `*sql.Rows` (or Query result) opened and used without Close cleanup, **without** requiring the identifier `rows` or the exact assignment text `rows, err := db.Query(`.

### Options considered

| Approach | What facts give today | Why it fails §1.3 |
|----------|----------------------|-------------------|
| **A. call_facts primary on `db.Query` / `*.Query`** | `CallFact { callee, arguments, start_byte }` — no receiver binding, no assigned LHS, no defer edge | Cannot pair Query result with a later `Close` on the same value. Unit-local “any Query, no Close string” mass-FPs returned rows, helper-closed cursors, `rows.Close()` without `defer`, and multi-Query units. |
| **B. AssignmentFact + method Close** | Assignments store `name` + raw `expr` text; Close appears as callee text like `rows.Close` | Still identifier-coupled. Renaming `rows` → `orderRows` is exactly the renamed-negative §1.3 wants; current oracle would FN, and B without SSA/ownership cannot recover the link. |
| **C. SI soften: drop `rows` name, keep Query/Next/Close shapes** | Broader needles | Still corpus co-signal emit; Next/Close without ownership still FP/FN; does not meet “AST/call facts / taint primary” bar. |
| **D. CFG / ownership / liveness** | Not in GoUnitFacts | Would be the real upgrade path (track Query LHS → defer Close / early-return leak). Out of R8 scope; blocked on platform work. |

### Renamed-negative thought experiment

Vulnerable fixture with `orderRows, err := db.Query(...)` + `orderRows.Next()` and no Close:

- **Today:** silent (FN) — proves emit is fixture-identifier primary.
- **After honest rewrite:** must fire — requires ownership pairing we do not have.
- Shipping renamed fixtures now without the rewrite would only document FN; oracle-safe rewrite was not attempted in product code.

### Real-module evidence

G3 canary and this R8 re-canary: **0** hits on gopdfsuit / monsoon / go-retry under `--only CWE-619,CWE-917`. Zero useful hits ⇒ no promotion evidence; FO quarantine remains consistent.

### Verdict (619)

**Keep fixture-only.** Do not promote. Do not ship a partial call_facts “primary” that still gates on `rows` (that would fake §1.3).

---

## Design proof — CWE-917 (template source concatenation)

### Goal

Emit when caller-controlled data is concatenated into `template.Parse` source, **without** exact `"report"`, `{{.Title}} where `, or `+ expr` corpus gates.

### Options considered

| Approach | What facts give today | Why it fails §1.3 |
|----------|----------------------|-------------------|
| **A. call_facts on `template.New(...).Parse` / `Parse`** | Chained callee text may match museum shape; args are raw source snippets | Legitimate builders concat constant fragments into Parse all the time. Parse alone is not the defect. |
| **B. SI: any `Parse(` + `+` concat** | Broader than `"report"` | Mass-FP on safe template assembly; still not taint-primary. |
| **C. Taint-core fold (CWE-22/78/79/89/90/91 neighbor)** | Taint graph exists behind config | Orthogonal contract: EL/template-*source* injection vs sink injection into queries/HTML. Needs a written FP/FN contract (G3 freeze already deferred this). Not R8. |
| **D. Dataflow: user input → string concat → Parse arg** | Assignments + input_bindings are partial; no concat AST / Parse-arg binding | Required for true generalization; not available as a complete primary today. |

### Renamed-negative thought experiment

Vulnerable: `template.New("summary").Parse("{{.Name}} filter " + expr)` with `expr` from query:

- **Today:** silent — formula requires `"report"`, `{{.Title}} where `, `+ expr`.
- **Safe museum** uses `reportTemplate` / `reportTemplatePure` constants — rename-safe only because negatives are also corpus names.

### Real-module evidence

Same 0/126 canary as 619. No actionable real-module hit to justify Heuristic keep.

### Verdict (917)

**Keep fixture-only.** Orthogonal to taint-core; do not fold without a written contract. No maturity uplift.

---

## §1.3 structural bar checklist

| Requirement | CWE-619 | CWE-917 |
|-------------|---------|---------|
| Primary match AST / call facts / taint — not fixture formula | ❌ SI museum | ❌ SI museum |
| Needles only as negative prefilters | ❌ Needles emit | ❌ Needles emit |
| Renamed / structurally varied near-miss fixtures | ❌ Not shipped (would FN) | ❌ Not shipped |
| Reviewed real-module hit or documented FP boundary for keep | ❌ 0 canary hits | ❌ 0 canary hits |
| Maturity + profile update in same change | N/A — no promotion | N/A — no promotion |

---

## Disposition table

| Rule | Before R8 | After R8 | Notes |
|------|-----------|----------|-------|
| **CWE-619** | fixture-only (G3) | **fixture-only** (kept) | Ownership/Close pairing blocked |
| **CWE-917** | fixture-only (G3) | **fixture-only** (kept) | Template concat without corpus literals blocked |
| **CWE-93** | Structural (header.rs) | unchanged | Out of R8 scope |

No Heuristic keep. No Structural uplift. No deletes.

---

## Integrator proposals

**None for maturity / NEEDLES.** Both rules are already correctly labeled FO in `maturity.rs` and NEEDLES comments in `source_index.rs` from G3. Integrator should **not** change maturity unless a future tranche lands ownership/taint primary + renamed negatives + real-module evidence.

Optional follow-up (backlog only, not this PR):

- Cursor ownership / defer-Close CFG analysis for a future 619 rewrite.
- Template-source taint contract distinct from taint-core sinks for a future 917 rewrite.

---

## Canary (2026-07-22)

Release binary built on this branch (`cargo build --release --locked`). Target revisions match `plans/v0.0.5/canary-corpus.md` pins:

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

Paths: `/home/chinmay/ChinmayPersonalProjects/gopdfsuit`; main-repo
`/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/{monsoon,go-retry}` (worktree has no local `real-repos/`).

### Tests

- `make lint` — clean
- `go_cwe_detector_fixtures` — 4/4 passed
- Full suite under parallel nextest: 457/459; known WSL/load timing flakes
  (`large_baseline_loads_and_filters_under_target`, `taint_extraction_overhead_is_small`)
  re-ran green serially (`--test-threads 1`). Unrelated to this docs/comment PR.

---

## Files touched (this PR)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/injection/resource.rs` | R8 design-attempt / keep-FO comments (oracle-safe) |
| `plans/v0.0.6/residual-injection-resource-generalize.md` | Checklist complete |
| `plans/v0.0.6/evidence-r8-injection-resource.md` | This evidence |
| `plans/v0.0.6/pr-r8-injection-resource.md` | PR body |

Explicit non-edits: `maturity.rs`, `source_index.rs`, `header.rs`, R5–R7, G*, P1.

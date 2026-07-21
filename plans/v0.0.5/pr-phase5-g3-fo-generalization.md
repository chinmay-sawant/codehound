# chore(phase5): G3 fixture-only residual family disposition

## Summary

- **G3** under epic [#136](https://github.com/chinmay-sawant/codehound/issues/136) / issue [#139](https://github.com/chinmay-sawant/codehound/issues/139).
- **One cohesive family only:** injection resource residual — **CWE-619** + **CWE-917** in `src/lang/go/detectors/cwe/domains/injection/resource.rs` (deferred C1 sibling after CWE-93 Structural).
- Freeze evidence (oracle-preserving; no emit rewrite). Pure SI museums → **apply fixture-only** maturity + NEEDLES labels.
- No bulk catalog relabel. No Structural promotion without §1.3.

**Closes #139** · **Relates to #136**

---

## Motivation / context

Phase 3 C1 selected `header.rs` (CWE-93 Structural) and **deferred** `resource.rs` as pure SourceIndex museums ([`pr-cwe-trust-injection-residual.md`](./pr-cwe-trust-injection-residual.md)). G3 owns FO residual disposition for one family at a time when corpus co-signals cannot become production proof.

| Candidate family | Rules | Why select / not |
|------------------|-------|------------------|
| **injection/resource (selected)** | CWE-619, CWE-917 | Explicit C1 deferred sibling; exact SI formulas; FO disposition already proposed |
| secrets_in_config | CWE-260, CWE-455 | Deferred env-requiredness / fail-fast policy — separate residual |
| sensitive_fields | CWE-201, CWE-213 | Already call-facts on response sinks; residual is field-name inventory, not pure SI |

---

## Evidence freeze

### CWE-619 — Dangling Database Cursor

| Axis | Frozen state |
|------|----------------|
| Primary SI | `rows, err := db.Query(` ∧ `rows.Next()` ∧ ¬`defer rows.Close()` |
| Negatives | `defer rows.Close()` |
| Emit span | `source.find("rows, err := db.Query(")` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (after) | **fixture-only** |

**Corpus vs real sink:** exact identifier `rows` + Query/Next/Close co-presence. Not generalized `*sql.Rows` ownership / early-return liveness.

### CWE-917 — Expression Language Injection (template source)

| Axis | Frozen state |
|------|----------------|
| Primary SI | `template.New("report").Parse(src)` ∧ `{{.Title}} where ` ∧ `+ expr` |
| Negatives | `reportTemplate` / `reportTemplatePure` |
| Emit span | `source.find("{{.Title}} where ")` |
| Fixtures | frameworks + stdlib vulnerable/safe pairs |
| Maturity (after) | **fixture-only** |

**Corpus vs real sink:** exact template name `"report"`, fixed fragment, concat co-signal. Not generalized user→`Parse` dataflow. Orthogonal to taint-core.

### Call-facts primary rewrite

**Not applied.** Both rules are pure museums: any call_facts-only primary would either mass-FP (any Query without Close; any `template.Parse`+concat) or still require the same corpus co-signals as emit gates. G3 FO residual path is honest quarantine, not fake generalization.

---

## Changes

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/injection/resource.rs` | Module + per-rule freeze docs; emit path unchanged |
| `src/lang/go/detectors/cwe/domains/injection/header.rs` | Sibling note: resource FO under G3 |
| `src/rules/maturity.rs` | `CWE-619` / `CWE-917` → `is_fixture_only` + unit asserts |
| `src/lang/go/detectors/cwe/source_index.rs` | NEEDLES labels for resource museum tokens |
| `plans/v0.0.5/cwe-catalog-trust-audit.md` | §2.16 G3 residual disposition |
| `plans/v0.0.5/phase5-implementation-backlog.md` | Residual table + G3 partial progress |
| `plans/v0.0.5/phase5-gated-work.md` | G3 Partial status + FO residual path |
| `plans/v0.0.5/pr-phase5-g3-fo-generalization.md` | This PR body |

### Dispositions

| Rule | Before | After | Rationale |
|------|--------|-------|-----------|
| **CWE-619** | Heuristic default | **fixture-only** | Exact `rows` Query/Next/Close formula |
| **CWE-917** | Heuristic default | **fixture-only** | Exact `template.New("report")` + fragment corpus |
| CWE-93 | Structural | Structural (unchanged) | Header sibling; not reopened |

### NEEDLES labels

| Needle | Label |
|--------|-------|
| `rows, err := db.Query(` | fixture-literal (CWE-619) |
| `rows.Next()` | fixture-literal / co-signal (CWE-619) |
| `defer rows.Close()` | negative-gate (CWE-619 safe-path) |
| `template.New("report").Parse(src)` | fixture-literal (CWE-917) |
| `{{.Title}} where ` | fixture-literal (CWE-917) |
| `+ expr` | fixture-literal (CWE-917) |
| `reportTemplate` / `reportTemplatePure` | negative-gate (CWE-917 safe-path) |

---

## Out of scope

- secrets_in_config (260/455), sensitive_fields (201/213), other FO families
- Bulk FO → Heuristic/Structural flips
- Structural promotion of 619/917 without §1.3 ownership/dataflow rewrite
- Taint-core ownership changes
- Fixture renames / new fixture files / manifest edits

---

## Canary (release binary)

```sh
cargo build --release --locked
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
  /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all \
    --only CWE-619,CWE-917 \
    --format json --json-envelope --no-fail --no-cache 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print('findings', len(d.get('findings',[])), 'files', d.get('stats',{}).get('files_scanned'))"
done
```

| Repository | Path | Revision | Files scanned | Findings |
|---|---|---|---:|---:|
| gopdfsuit | `/home/chinmay/ChinmayPersonalProjects/gopdfsuit` | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **0** |
| monsoon | `codehound/real-repos/monsoon` | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | **0** |
| go-retry | `codehound/real-repos/go-retry` | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | **0** |

**Totals:** 126 scanned files (78+43+5). Per-rule: CWE-619 ×0, CWE-917 ×0.

**Decision:** FO quarantine for pure museums; quiet canary (0/126) supports keep-as-FO (not Structural). Fixtures remain regression evidence under `--profile all` / `--only`.

---

## Validation

```sh
make lint
cargo test --locked --test go_cwe_detector_fixtures
make test
git diff --check
```

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior / fixtures** | Oracle preserved (emit path unchanged) |
| **Packs** | CWE-619/917 quarantined from recommended/security (still under `--profile all` / `--only`) |
| **Performance** | Neutral (comments + maturity match arms + NEEDLE comments) |
| **API / CLI** | None |

---

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4 passed)
- [x] `make test` (at commit time)
- [x] `git diff --check`
- [x] Release canary `--only CWE-619,CWE-917` on gopdfsuit, monsoon, go-retry (**0/126**)
- [x] Confirm vulnerable fixtures fire and safe fixtures silence for both rules
- [x] Confirm `maturity_for("CWE-619"|"CWE-917") == FixtureOnly`

## Related issues

- Closes #139
- Relates to #136
- Continues C1 deferred sibling from #112 / epic #105 Phase 3

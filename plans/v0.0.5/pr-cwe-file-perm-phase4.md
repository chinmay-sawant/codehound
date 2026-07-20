# docs(cwe): file-permissions Phase 4 validation and audit §2.12

## Summary

- Close Phase 4 of the access-control file-permissions CWE trust tranche: validation gate + documentation.
- Append dated audit **§2.12** with proposed dispositions for CWE-276 / 277 / 278 / 279 / 281 / 921 from master source review.
- Update plan checkboxes/status and point `cwe-catalog-trust-45.md` at epic #85 / issue #89.
- **Docs-only** — no `maturity.rs`, detector, profile, or fixture-manifest changes (Phase 2 owns code; Phase 3 owns canary).

---

## Motivation / context

Epic [#85](https://github.com/chinmay-sawant/codehound/issues/85) splits the file-permissions sibling audit into phases. Issue [#89](https://github.com/chinmay-sawant/codehound/issues/89) is Phase 4: run the validation suite and record dispositions so integration can reconcile when Phase 2/3 land.

Parent lineage: long-tail under [#45](https://github.com/chinmay-sawant/codehound/issues/45) §2.11 inventory named these six rules as the next domain-sized batch.

Plans:

- `plans/v0.0.5/cwe-file-permissions-trust.md`
- `plans/v0.0.5/cwe-catalog-trust-audit.md` §2.12
- `plans/v0.0.5/cwe-catalog-trust-45.md`

---

## Changes

### Documentation

| Doc | Change |
|-----|--------|
| `cwe-catalog-trust-audit.md` | Status line + new **§2.12 File-permissions sibling disposition** table (disposition, evidence, canary note) |
| `cwe-file-permissions-trust.md` | Tracked plan; Phase 4 checkboxes complete; Phase 1 evidence closed; Phase 2/3 ownership notes |
| `cwe-catalog-trust-45.md` | Pointer to epic #85 / #89 / §2.12; code changes require scoped issues |
| `pr-cwe-file-perm-phase4.md` | This PR body |

### Proposed dispositions (not enforced on this branch)

| Rule | Disposition | Rationale (short) |
|------|-------------|-------------------|
| CWE-276 | fixture-only | session path / `session_data` / `X-Session-Data` co-signals |
| CWE-277 | keep Heuristic | `Umask(0)` + `MkdirAll` `0777` production-shaped |
| CWE-278 | keep Heuristic | `OpenFile` + `FileMode(hdr.Mode)` production-shaped |
| CWE-279 | fixture-only | `ParseUint` co-presence + hard-coded WriteFile `0777` |
| CWE-281 | fixture-only | exact `io.Copy(out, in)` fixture formula |
| CWE-921 | fixture-only | `/tmp/integration.key` corpus path |

Canary: **pending integration canary** (Phase 3).

### Explicitly not changed

- `src/rules/maturity.rs` / profile packs
- `file_modes.rs` detectors / `source_index.rs`
- Fixture files / `tests/fixtures/manifest.toml`
- `plans/v0.0.5/pending-work.md` (no ownership/roadmap change)

---

## Validation

```sh
cargo test --locked --test go_cwe_detector_fixtures
cargo test --locked --lib rules::maturity
make lint
make test
git diff --check
```

All green on branch `docs/cwe-file-perm-phase4-closure`. No unrelated rule/profile/fixture-manifest churn.

---

## Integration notes / blockers

1. **Phase 2** must apply `is_fixture_only` for CWE-276/279/281/921 (+ tests) and optional family NEEDLES labels. This PR documents intent only.
2. **Phase 3** must record gopdfsuit / monsoon / go-retry canary totals into §2.12 (replace “pending integration canary”).
3. Integration merge order: Phase 2 code → Phase 3 canary numbers → this docs section already names proposed dispositions so conflicts are textual only.
4. No structural promotion for any of the six rules under §1.3.

---

## Closes

- Closes [#89](https://github.com/chinmay-sawant/codehound/issues/89)
- Relates to [#85](https://github.com/chinmay-sawant/codehound/issues/85)

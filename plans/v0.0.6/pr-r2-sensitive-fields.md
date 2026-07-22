# chore(cwe): audit sensitive_fields trust (R2)

## Summary

- v0.0.6 slice **R2** — freeze evidence, dispositions, and oracle-safe documentation for the **sensitive_fields** response-leak subfamily (**CWE-201**, **CWE-213**), deferred sibling from Phase 2 B2 (`metadata_leaks` only in #108).
- Both rules already use **call_facts primary** on production-shaped JSON response sinks (`c.JSON`, `json.NewEncoder(w).Encode`); SI retains field/type inventory co-signals and CWE-213 redaction DTO negatives.
- **CWE-201 / CWE-213**: **keep Heuristic** (generalized sinks, not exact response literals; field inventory noise control; not structural — §1.3).
- Propose maturity/NEEDLES only for integrator; shared surfaces untouched.

---

## Motivation / context

Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151) batches residual CWE catalog-trust families for v0.0.6. Issue [#159](https://github.com/chinmay-sawant/codehound/issues/159) is slice R2 under `plans/v0.0.6/residual-sensitive-fields.md`.

**Integration base SHA:** `0ff071f`

Owner seam: `src/lang/go/detectors/cwe/domains/information_exposure/response_leaks/sensitive_fields.rs`

**Deferred sibling context:** B2 (#108) selected `metadata_leaks.rs` because §2.2 targeted exact error/body/header literals; `sensitive_fields` was deferred as already call-facts-on-JSON-sink with field-name inventory risk.

---

## Changes

### Detector (`sensitive_fields.rs` only)

| Rule | Change |
|------|--------|
| CWE-201 | Freeze comments: call_facts primary on JSON sink + arg `record`; SI co-signals `APIKey`/`TokenKey` + record type; safe path = redacted DTO (call-facts arg mismatch); **keep Heuristic** |
| CWE-213 | Freeze comments: call_facts primary on JSON sink + arg `profile`; SI co-signals `Salary`/`Comp`; SI negatives `guestProfile{`/`directoryEntry{`; **keep Heuristic** |

**No emit-path, span, or needle changes** — detector already emitted at JSON sink call site.

### Plans / evidence

| Path | Change |
|------|--------|
| `plans/v0.0.6/residual-sensitive-fields.md` | Checklist completed |
| `plans/v0.0.6/evidence-r2-sensitive-fields.md` | Full freeze inventory, disposition, canary |
| `plans/v0.0.6/pr-r2-sensitive-fields.md` | This PR body |

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs`, `source_index.rs`, profile allow-lists, `manifest.toml`
- `cwe-catalog-trust-audit.md`, `parallel-catalog-program.md`
- Sibling `metadata_leaks.rs`; R1 `secrets_in_config`; R3–R8; G*; P1
- No new fixture files; no fixture renames

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None — comments/reorder only |
| **Memory** | None |
| **Behavior / correctness** | None — oracle preserved |
| **API / CLI** | None |
| **Dependencies** | None |
| **Binary size / build time** | None |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

---

## Test plan

- [x] `make lint`
- [x] `make test`
- [x] Focused CWE-201 / CWE-213 fixture tests
- [x] Canary on pinned corpus (gopdfsuit + real-repos)

### Commands

```sh
make lint
make test
cargo test cwe_201 -- --nocapture
cargo test cwe_213 -- --nocapture
# Canary — see evidence-r2-sensitive-fields.md
```

---

## Proposed dispositions (integrator)

| Rule | Disposition | Call-facts | Rationale |
|------|-------------|------------|-----------|
| CWE-201 | **keep Heuristic** | yes — JSON sink + `record` arg | Generalized response sink; field/type inventory co-signals; not structural |
| CWE-213 | **keep Heuristic** | yes — JSON sink + `profile` arg | Generalized response sink; comp-field inventory + redaction DTO negatives |

Do **not** fixture-only quarantine (unlike metadata_leaks museum literals). Do **not** structural-promote either rule.

### Proposed NEEDLES labels (integrator applies in `source_index.rs`)

| Needle | Proposed label |
|--------|----------------|
| `APIKey` / `TokenKey` | co-signal (CWE-201 field inventory) |
| `type userRecord struct` / `type memberRecord struct` | `fixture-literal` (CWE-201 record types) |
| `Salary` / `Comp` | co-signal (CWE-213 comp inventory) |
| `guestProfile{` / `directoryEntry{` | `negative-gate` (CWE-213 redaction DTO) |

### Proposed maturity.rs (integrator)

Leave CWE-201 and CWE-213 as default **Heuristic** (not in `is_fixture_only`). Optional inline comments when epic #151 integration lands.

---

## Integration

This branch is also merged into epic #151 R1–R4 integration (when present) for combined validation. Prefer reviewing/merging the integration PR when present.

---

## Related issues

- Closes #159
- Relates to #151

---

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r2-sensitive-fields.md`

---

## Follow-ups (out of scope)

- R1 secrets_in_config (#158), R3 auth_flows (#160), R4 auth_tokens (#161)
- Structural promotion without §1.3 real-module evidence
- Broadening to generic JSON serialization of any struct with sensitive field names

---

## Reviewer checklist

- [ ] Behavior matches summary and test plan
- [ ] No unrelated changes in diff
- [ ] Fixture oracle unchanged (8 CWE-201/213 files)
- [ ] Shared surfaces untouched per worker contract

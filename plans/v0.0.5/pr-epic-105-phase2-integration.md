# chore: integrate epic #105 Phase 2 catalog trust batch

## Summary

Single integration of Phase 2 parallel catalog streams (B1–B4): credential lifecycle credentials-in-source, response metadata leaks, auth cookies, and privilege escalation. Applies shared maturity quarantine and NEEDLES labels, records audit §2.14, and validates with full suite + combined canary.

---

## Motivation / context

- Plan: [`plans/v0.0.5/parallel-catalog-program.md`](./parallel-catalog-program.md) Phase 2
- Audit: [`plans/v0.0.5/cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §2.14
- Parent epic: #105 (Phase 3–5 remain open)
- Integration base SHA: `9d66183c3b29d8589317328170226bff6d4323d1`
- Child PRs are **superseded** by this integration PR

---

## Child streams

| Issue | Slice | Branch | Standalone PR | Outcome |
|------:|-------|--------|---------------|---------|
| #107 | B1 credentials-in-source | `chore/cwe-trust-credential-lifecycle` | #124 | 523/547 FO; 798 reaffirm FO |
| #108 | B2 metadata_leaks | `chore/cwe-trust-response-leaks` | #125 | 209/756/1230 FO; **215 Heuristic** |
| #109 | B3 cookies | `chore/cwe-trust-auth-validation` | #122 | 603/613 FO |
| #110 | B4 privilege_escalation | `chore/cwe-trust-privilege-lifecycle` | #123 | 266/267/268/270/273/274/1265 FO; **272 Heuristic** |
| #111 | Phase 2 integration | this branch | this PR | shared surfaces + canary |

---

## Changes

### Detectors (from children)

- `credential_lifecycle/credentials_in_source.rs` — freeze comments
- `response_leaks/metadata_leaks.rs` — call_facts primary for 209/756/1230; 215 docs
- `auth_and_validation/cookies.rs` — freeze comments
- `privilege_escalation/{role_scope,transitions}.rs` — freeze comments

### Shared surfaces (this PR)

- **`maturity.rs`** — fixture-only for Phase 2 FO list; Heuristic keep for CWE-215 and CWE-272; unit tests
- **`source_index.rs`** — selected NEEDLES labeled fixture-literal
- **Audit §2.14** + Phase 2 ledger checkboxes

### Fixtures / manifest

- Unchanged

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | Newly FO rules leave recommended/security packs; still under `--profile all` / `--only` |
| **Heuristic keep** | CWE-215 (secret-named log) and CWE-272 (Setuid+Chown) remain pack-eligible |
| **API / CLI** | Pack membership only |
| **Performance** | Neutral |

### Combined Phase 2 canary (integrated tree) — 2026-07-21

| Repository | Files scanned | Findings |
|---|---:|---:|
| gopdfsuit | 78 | **0** |
| monsoon | 43 | **0** |
| go-retry | 5 | **0** |

**Totals:** 126 files · all Phase 2 `--only` IDs ×0.

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| Newly fixture-only CWE IDs | Use `--profile all` or `--only` |
| CWE-215, CWE-272 Heuristic | No pack change |

---

## Test plan

- [x] Merge B1–B4 without conflicts
- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4 passed)
- [x] `make test` (443 nextest + 1 doctest)
- [x] `git diff --check`
- [x] `cargo build --release --locked`
- [x] Combined Phase 2 canary (0 findings / 126 files)

```sh
ONLY=CWE-523,CWE-547,CWE-798,CWE-209,CWE-215,CWE-756,CWE-1230,CWE-603,CWE-613,CWE-266,CWE-267,CWE-268,CWE-270,CWE-272,CWE-273,CWE-274,CWE-1265
```

---

## Related issues

- Closes #107
- Closes #108
- Closes #109
- Closes #110
- Closes #111
- Relates to #105 (parent epic; Phase 3–5 remain)

---

## PR metadata checklist (author)

- [x] Self-assigned
- [x] Labels: documentation + enhancement
- [x] Related issues filled
- [x] Body under `plans/v0.0.5/pr-epic-105-phase2-integration.md`

---

## Follow-ups (out of scope)

- Phase 3 C1–C4 (#112–#116)
- Phase 4 product trust (#117–#119)
- Phase 5 trackers (#120–#121)
- Deferred Phase 2 siblings (expiration, sensitive_fields, auth_flows/tokens, lifecycle_and_integrity)

---

## Release notes

Quarantine additional corpus-shaped CWE rules from default packs after Phase 2 catalog trust audit; keep CWE-215 and CWE-272 as Heuristic.

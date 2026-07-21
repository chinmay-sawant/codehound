# chore: integrate epic #151 R1–R4 residual trust

## Summary

Single integration of epic #151 Class B residual trust streams R1–R4 (secrets_in_config, sensitive_fields, auth_flows, auth_tokens). Merges four child branches, applies shared maturity quarantine + NEEDLES labels, updates the v0.0.6 ledger for #158–#161, and validates with full suite.

**Child PRs are superseded** by this integration PR — prefer reviewing/merging this PR.

Epic #151 remains open (G* gated workstreams + R5+ residuals + P1 remain).

---

## Child streams

| Issue | Stream | Branch | Standalone PR | Maturity outcome |
|------:|--------|--------|---------------|------------------|
| #158 | R1 secrets_in_config | `chore/cwe-trust-secrets-in-config` | #167 | **CWE-260, CWE-455 → fixture-only** |
| #159 | R2 sensitive_fields | `chore/cwe-trust-sensitive-fields` | #169 | **CWE-201, CWE-213 keep Heuristic** |
| #160 | R3 auth_flows (bounded) | `chore/cwe-trust-auth-flows` | #168 | **CWE-289, CWE-290 → fixture-only** |
| #161 | R4 auth_tokens (bounded) | `chore/cwe-trust-auth-tokens` | #170 | **CWE-294, 301, 303, 322, 408 → fixture-only** |

Merge order: R1 → R2 → R3 → R4 (no conflicts).

---

## Changes

### Detectors (from children — freeze / trust comments only)

- `configuration/secrets_in_config.rs` — CWE-260 / 455 freeze
- `response_leaks/sensitive_fields.rs` — CWE-201 / 213 freeze (call_facts primary retained)
- `auth_and_validation/auth_flows.rs` — CWE-289 / 290 freeze
- `auth_and_validation/auth_tokens.rs` — CWE-294 / 301 / 303 / 322 / 408 freeze

### Shared surfaces (integrator)

- **`src/rules/maturity.rs`** — fixture-only for 260, 455, 289, 290, 294, 301, 303, 322, 408; Heuristic keep asserted for 201 / 213; unit tests
- **`src/lang/go/detectors/cwe/source_index.rs`** — selected NEEDLES labeled `fixture-literal` / `negative-gate` / co-signal per worker handoffs (dual-use needles such as `tls.LoadX509KeyPair(` / `hmac.New(` left unlabeled)
- **`plans/v0.0.6/pending-work.md`** — Class B #158–#161 checked `[x]`; ledger plan stubs included

### Fixtures / manifest

- Unchanged IDs and oracles (no new fixtures; no `manifest.toml` edits)

---

## Handoff maturity summary

| Rule | Disposition | Rationale (worker evidence) |
|------|-------------|-----------------------------|
| CWE-260 | fixture-only | Env-requiredness museum; not project-agnostic |
| CWE-455 | fixture-only | Fail-fast / degraded-mode policy museum |
| CWE-201 | Heuristic keep | Production JSON sink (call_facts) + field inventory |
| CWE-213 | Heuristic keep | Production JSON sink (call_facts) + comp-field inventory |
| CWE-289 | fixture-only | Exact `"@")[0]` + principals SQL museum |
| CWE-290 | fixture-only | Exact `X-Remote-User` header trust museum |
| CWE-294 | fixture-only | auth_token + nonce co-signal museum |
| CWE-301 | fixture-only | challenge→proof echo museum |
| CWE-303 | fixture-only | `string(expected) == sig` MAC museum |
| CWE-322 | fixture-only | tls.Dial + InsecureSkipVerify museum |
| CWE-408 | fixture-only | orders SELECT before Authorization source-order museum |

---

## Combined validation

### Child canaries (pre-integration, pinned corpus)

| Stream | Rules | Files | Findings |
|--------|-------|------:|---------:|
| R1 | 260, 455 | 376 | 0 |
| R2 | 201, 213 | 376 | 0 |
| R3 | 289, 290 | 376 | 0 |
| R4 | 294, 301, 303, 322, 408 | 126* | 0 |

\*R4 worker recorded gopdfsuit + monsoon + go-retry (126 files); R1–R3 used the wider pinned set (376).

### Integration branch

- [x] Merge R1–R4 (clean; no conflicts)
- [x] Apply maturity + NEEDLES
- [x] `make lint`
- [x] `make test`

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | Newly FO rules leave recommended/security packs; still under `--profile all` / `--only` |
| **Heuristic keep** | CWE-201, CWE-213 remain pack-eligible |
| **API / CLI** | Pack membership only |
| **Performance** | Neutral |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| Newly fixture-only CWE IDs (260, 455, 289, 290, 294, 301, 303, 322, 408) | Use `--profile all` or `--only` |
| CWE-201, CWE-213 Heuristic | No pack change |

---

## Related issues

- Closes #158
- Closes #159
- Closes #160
- Closes #161
- Relates to #151

---

## PR metadata

- [x] Assignee @me
- [x] Labels documentation + enhancement

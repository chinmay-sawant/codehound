# chore: integrate epic #151 R5–R8 residual trust

## Summary

Single integration of epic #151 Class B residual trust streams R5–R8 (credential expiration/aging, credential reset/recovery, lifecycle_and_integrity plugins, injection resource generalization evaluation). Merges four child branches, applies shared maturity quarantine + selected NEEDLES labels, updates the v0.0.6 ledger for #162–#165, and validates with full suite.

**Child PRs are superseded** by this integration PR — prefer reviewing/merging this PR.

Epic #151 remains open (G* gated workstreams + P1 remain).

---

## Child streams

| Issue | Stream | Branch | Standalone PR | Maturity outcome |
|------:|--------|--------|---------------|------------------|
| #162 | R5 credential expiration / aging | `chore/cwe-trust-credential-expiration` | #175 | **CWE-324, 262, 263 → fixture-only** |
| #163 | R6 credential reset / recovery | `chore/cwe-trust-credential-reset` | #173 | **CWE-549, 640 → fixture-only** |
| #164 | R7 lifecycle_and_integrity (plugins.rs) | `chore/cwe-trust-lifecycle-integrity` | #174 | **CWE-618, 829, 1125 → fixture-only** |
| #165 | R8 injection resource generalize | `chore/cwe-trust-injection-resource` | #172 | **CWE-619, 917 keep FO** (already FO from G3) |

Merge order: R5 → R6 → R7 → R8 (no conflicts).

---

## Changes

### Detectors (from children — freeze / trust comments only)

- `credential_lifecycle/key_expiration.rs` — CWE-324 freeze
- `credential_lifecycle/password_aging.rs` — CWE-262 / 263 freeze
- `credential_lifecycle/reset_recovery.rs` — CWE-549 / 640 freeze
- `lifecycle_and_integrity/plugins.rs` — CWE-618 / 829 / 1125 freeze
- `injection/resource.rs` — R8 keep-FO evaluation (no maturity uplift)

### Shared surfaces (integrator)

- **`src/rules/maturity.rs`** — fixture-only for 324, 262, 263, 549, 640, 618, 829, 1125; 619 / 917 unchanged FO; unit tests
- **`src/lang/go/detectors/cwe/source_index.rs`** — selected NEEDLES labeled `fixture-literal` / `negative-gate` per worker handoffs (dual-use generics such as `hmac.New(`, `exec.Command(`, `plugin.Open(`, `time.Since(`, `"token"`, `path := ` left unlabeled)
- **`plans/v0.0.6/pending-work.md`** — Class B #162–#165 checked `[x]`; R5–R8 struck from recommended order

### Fixtures / manifest

- Unchanged IDs and oracles (no new fixtures; no `manifest.toml` edits)

---

## Handoff maturity summary

| Rule | Disposition | Rationale (worker evidence) |
|------|-------------|-----------------------------|
| CWE-324 | fixture-only | ExpiresAt + key-row + hmac museum; out-of-unit expiry possible |
| CWE-262 | fixture-only | last_seen/changed_at without aging — org policy museum |
| CWE-263 | fixture-only | Exact `MaxAgeDays: 3650` threshold museum |
| CWE-549 | fixture-only | Exact `"password": pass` response-echo museum |
| CWE-640 | fixture-only | ForgotPassword + email-only UPDATE museum |
| CWE-618 | fixture-only | Vendor activex-bridge + exec method/args museum |
| CWE-829 | fixture-only | `plugin.Open` + caller path markers without allowlist |
| CWE-1125 | fixture-only | MountWideSurface + debug/admin/internal route museum |
| CWE-619 | keep FO | Already FO from G3; R8 found no ownership/taint primary path |
| CWE-917 | keep FO | Already FO from G3; R8 found no AST/call_facts primary path |

---

## Combined validation

### Child canaries (pre-integration, pinned corpus)

| Stream | Rules | Files | Findings |
|--------|-------|------:|---------:|
| R5 | 324, 262, 263 | 376 | 0 |
| R6 | 549, 640 | 376 | 0 |
| R7 | 618, 829, 1125 | 376 | 0 |
| R8 | 619, 917 | 126* | 0 |

\*R8 worker recorded the narrower pinned set (same as G3); R5–R7 used the wider pinned set (376).

### Integration branch

- [x] Merge R5–R8 (clean; no conflicts)
- [x] Apply maturity + NEEDLES
- [x] `make lint`
- [x] `make test`

---

## Impact

| Area | Impact |
|------|--------|
| **Behavior** | Newly FO rules leave recommended/security packs; still under `--profile all` / `--only` |
| **Keep FO** | CWE-619, CWE-917 unchanged |
| **API / CLI** | Pack membership only |
| **Performance** | Neutral |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| Newly fixture-only CWE IDs (324, 262, 263, 549, 640, 618, 829, 1125) | Use `--profile all` or `--only` |
| CWE-619, CWE-917 | Already FO — no new pack change |

---

## Related issues

- Closes #162
- Closes #163
- Closes #164
- Closes #165
- Relates to #151

---

## PR metadata

- [x] Assignee @me
- [x] Labels documentation + enhancement

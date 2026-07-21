# chore: integrate epic #95 CWE catalog trust batch 1

## Summary

Integrate four parallel catalog-trust workstreams (password storage, transport secrets, deserialization, access-control authorization) with shared maturity, SourceIndex labels, audit ledger, and the worktree-delegation skill. Quarantine museum-shaped rules from default packs; keep CWE-916 Heuristic after reviewed real-module hits.

---

## Motivation / context

- Plan: [`plans/v0.0.5/parallel-catalog-program.md`](./parallel-catalog-program.md) Phase 0–1
- Audit: [`plans/v0.0.5/cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) §2.13
- Process: [`plans/skills/worktree-deleation/SKILL.md`](../skills/worktree-deleation/SKILL.md)
- Integration base SHA: `217c0078d8a585e0e08b3b113e665898f6bf62dd`
- Issues: see **Related issues**

Child PRs are **superseded** by this integration PR (prefer merge integration only).

---

## Child streams

| Issue | Slice | Branch | Standalone PR | Disposition summary |
|------:|-------|--------|---------------|---------------------|
| #96 | A1 password storage | `chore/cwe-trust-password-storage` | #103 | 256/257/261 fixture-only; **916 Heuristic** |
| #97 | A2 transport secrets | `chore/cwe-trust-transport-secrets` | #102 | 524/538 fixture-only |
| #98 | A3 deserialization | `chore/cwe-trust-deserialization` | #101 | 502 fixture-only |
| #99 | A4 authorization_and_scoping | `chore/cwe-trust-access-control` | #100 | 425/551/653/639/1220 fixture-only; auth_and_validation deferred → Phase 2 B3 |

---

## Changes

### Detectors (from children)

- **password_storage/hashing.rs** — call_facts primary for 257/261/916; 256 freeze comments only
- **secrets_and_transport/transport.rs** — call_facts primary for 538 WriteFile+0o644; 524 comments only
- **deserialization/decoders.rs** — call_facts primary for gob.NewDecoder; corpus co-signals non-primary
- **authorization_and_scoping/{guards,scoping}.rs** — proof-boundary comments only (no call-facts rewrite)

### Shared surfaces (integration-only)

- **`maturity.rs`** — fixture-only for CWE-256, 257, 261, 524, 538, 502, 425, 551, 653, 639, 1220; Heuristic keep for CWE-916; unit tests extended
- **`source_index.rs`** — batch-1 NEEDLES labeled `fixture-literal` / `negative-gate` (no bulk deletes)
- **Audit §2.13** + **parallel-catalog-program** Phase 0–1 checkboxes
- **Skill** `plans/skills/worktree-deleation/SKILL.md` + issue body records under `plans/v0.0.5/issues/`

### Fixtures / manifest

- Unchanged (oracle preserved; no new boundary fixtures)

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Neutral |
| **Memory** | Negligible |
| **Behavior / correctness** | Quarantined IDs leave recommended/security packs; still under `--profile all` / `--only`. CWE-916 remains pack-eligible Heuristic |
| **API / CLI** | Pack membership for newly quarantined IDs |
| **Dependencies** | None |

### Combined Phase 1 canary (integrated tree) — 2026-07-21

Source binary built from this integration branch (`cargo build --release --locked`).

| Repository | Revision (pinned prior canaries) | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | **2** (CWE-916 ×2) |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |

**Totals:** 126 files · per-rule: only CWE-916 ×2; all other batch-1 IDs ×0.

Sample hits:
- `internal/pdf/encryption/encrypt.go:79`
- `internal/pdf/redact/encryption_inhouse.go:241`

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| CWE-256, 257, 261, 524, 538, 502, 425, 551, 653, 639, 1220 → fixture-only | Use `--profile all` or `--only`; excluded from recommended/security default packs |
| CWE-916 remains Heuristic | No pack change |

---

## Test plan

- [x] Merge A1–A4 without conflicts
- [x] `make lint`
- [x] `cargo test --locked --test go_cwe_detector_fixtures` (4 passed)
- [x] `make test` (443 nextest + 1 doctest passed)
- [x] `git diff --check`
- [x] `cargo build --release --locked`
- [x] Combined canary:

```sh
ONLY=CWE-256,CWE-257,CWE-261,CWE-916,CWE-524,CWE-538,CWE-502,CWE-425,CWE-551,CWE-653,CWE-639,CWE-1220
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit real-repos/monsoon real-repos/go-retry; do
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache
done
```

### Commands

```sh
make lint
make test
```

---

## Related issues

- Closes #96
- Closes #97
- Closes #98
- Closes #99
- Closes #95
- Relates to #85 (prior file-permissions batch)
- Relates to #45 (long-tail catalog)

---

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels: documentation + enhancement
- [x] Related issues filled with real ticket IDs
- [x] Filled body under `plans/v0.0.5/pr-epic-95-integration.md`

---

## Follow-ups (out of scope)

- Phase 2 batches (credential lifecycle, response leaks, auth_and_validation sibling, privilege escalation)
- Structural promotion of CWE-916 or CWE-277
- BP expansion, typed Go facts, Python catalog

---

## Release notes (if user-facing)

Quarantine additional corpus-shaped CWE rules from default packs after evidence-backed trust audit; keep weak password MD5 (CWE-916) as Heuristic with real-module signal.

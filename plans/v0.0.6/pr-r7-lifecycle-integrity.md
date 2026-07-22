# chore(cwe): audit lifecycle_and_integrity trust (R7)

## Summary

- Inventory `general_security/lifecycle_and_integrity/`; **select** the bounded
  **`plugins.rs`** leaf (**CWE-618**, **CWE-829**, **CWE-1125** — ~92 lines).
- **Defer** `lifecycle.rs` (topology / lock-ownership / resource lifetime) and
  `runtime_state.rs` (cross-request covert channel + inconsistent failure topology).
- Freeze primary signals, negatives, fixtures, and maturity state for the selected leaf.
- Propose **fixture-only** dispositions for all three (integrator applies `maturity.rs` /
  SourceIndex NEEDLES labels).
- Oracle-safe detector comments only (no emit-path changes); run focused fixtures +
  three-rule real-module canary.

---

## Motivation / context

Residual catalog slice **R7** of issue
[#164](https://github.com/chinmay-sawant/codehound/issues/164). Relates to epic
[#151](https://github.com/chinmay-sawant/codehound/issues/151).

Phase 2 B4 (#110) dispositioned sibling `privilege_escalation/` and deferred the full
`lifecycle_and_integrity/` seam. This worker completes one bounded subfamily under the
v0.0.6 residual program — not the whole seam.

**Integration base SHA:** `79c9b29799436729699bc8f1a6aa18116fc4b316`  
**Branch:** `chore/cwe-trust-lifecycle-integrity`  
**Structural bar:** [`cwe-catalog-trust-audit.md`](../v0.0.5/cwe-catalog-trust-audit.md) §1.3  
**Worker contract:** [`parallel-catalog-program.md`](../v0.0.5/parallel-catalog-program.md) §0.2

---

## Selection inventory

### Owner seam — `lifecycle_and_integrity/`

| Leaf | Rules | Lines (approx) | Fixture coverage |
|------|-------|----------------|------------------|
| `lifecycle.rs` | CWE-765, 778, 826, 1322 | ~122 | stdlib + frameworks each |
| **`plugins.rs`** | **CWE-618, 829, 1125** | **~92** | **stdlib + frameworks each** |
| `runtime_state.rs` | CWE-515, 544, 605 | ~100 | stdlib + frameworks each |

### Why select `plugins.rs`

1. **Smallest cohesive leaf** — three rules with full oracle pairs; no boil-the-ocean.
2. **Clearest local sinks** — vendor native-bridge `exec.Command`, `plugin.Open`, mount-helper + route literals.
3. **Full fixture oracle** — vulnerable + safe for stdlib and frameworks; no new fixtures.
4. **Matches residual checklist** — clear sink + safe fixtures; topology/ownership deferred to siblings.
5. **Does not reopen** `privilege_escalation/` (B4 done).

Deferred within this seam (not in this PR): `lifecycle.rs`, `runtime_state.rs`.

---

## Frozen signals (selected family)

Runtime maturity today: all three default to **Heuristic**. Available under `--profile all` /
`--only`; not on recommended/security explicit allow-lists.

### CWE-618 — Exposed Unsafe ActiveX Method

| Field | Value |
|-------|--------|
| File | `plugins.rs` → `detect_cwe_618` |
| Primary signal | SI `/opt/vendor/activex-bridge` + `exec.Command(` + `method` + `args` |
| Negatives | SI `allowedPluginMethods` |
| Span | source find of `/opt/vendor/activex-bridge` |
| Call-facts? | No — `exec.Command` alone insufficient without vendor-path museum |
| **Proposed disposition** | **fixture-only** |

### CWE-829 — Inclusion of Functionality from Untrusted Control Sphere

| Field | Value |
|-------|--------|
| File | `plugins.rs` → `detect_cwe_829` |
| Primary signal | SI `plugin.Open(` + `module_path` \| `path := ` |
| Negatives | SI `allowedModules` / `moduleRoot` |
| Span | source find of `plugin.Open(` |
| Call-facts? | `plugin.Open` alone fires on safe allowlisted loads |
| **Proposed disposition** | **fixture-only** |

### CWE-1125 — Excessive Attack Surface

| Field | Value |
|-------|--------|
| File | `plugins.rs` → `detect_cwe_1125` |
| Primary signal | SI `MountWideSurface(` \| `MountWideSurfacePure(` + debug/admin/internal route literals |
| Negatives | SI `authRequired()` / `authRequiredPure(` |
| Span | source find of `/debug/pprof` |
| Call-facts? | No — route-set topology is corpus SI, not CFG |
| **Proposed disposition** | **fixture-only** |

### Disposition table

| Rule | Disposition | Primary signal class | Notes |
|------|-------------|----------------------|-------|
| **CWE-618** | **fixture-only** | SI vendor bridge + exec | Neighbor of injection; not duplicate |
| **CWE-829** | **fixture-only** | SI plugin.Open + caller path | Neighbor of CWE-426 PATH search |
| **CWE-1125** | **fixture-only** | SI MountWideSurface + routes | Route-set museum |

No rule proposed for Heuristic keep or Structural. No deletes. No §1.3 promotion.

---

## Changes

### Code (`lifecycle_and_integrity/plugins.rs` only)

- Proof-boundary comments freezing primary signal, negatives, call-facts assessment, and
  policy-evidence treatment of vendor paths / allowlists / mount helpers.
- **No emit logic, messages, or span changes** (oracle preserved).

### Docs

- `plans/v0.0.6/residual-lifecycle-integrity.md` — checklist complete
- `plans/v0.0.6/evidence-r7-lifecycle-integrity.md` — full evidence
- This PR body (`plans/v0.0.6/pr-r7-lifecycle-integrity.md`)

### Explicitly not changed (integrator / out of scope)

- `src/rules/maturity.rs` — propose adding all three to `is_fixture_only`
- `src/lang/go/detectors/cwe/source_index.rs` — propose NEEDLES labels (see evidence)
- profiles, `tests/fixtures/manifest.toml`, `cwe-catalog-trust-audit.md`, ledger
- `lifecycle.rs`, `runtime_state.rs`, `privilege_escalation/`
- R5, R6, R8, G*, P1 seams

---

## Integrator proposals

See `plans/v0.0.6/evidence-r7-lifecycle-integrity.md` § Proposed integrator changes.

### Maturity (`maturity.rs`)

Add to `is_fixture_only`: `CWE-618`, `CWE-829`, `CWE-1125`.

### Canary command (worker evidence; re-run after integration)

```sh
cargo build --release --locked
ONLY="CWE-618,CWE-829,CWE-1125"
for t in /home/chinmay/ChinmayPersonalProjects/gopdfsuit \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/monsoon \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/go-retry \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/gorl \
         /home/chinmay/ChinmayPersonalProjects/codehound/real-repos/no-mistakes; do
  echo "=== $t ==="
  target/release/codehound "$t" --profile all --only "$ONLY" \
    --format json --json-envelope --no-fail --no-cache
done
```

---

## Canary results (2026-07-22)

Release binary built on this branch (`cargo build --release --locked`). Target revisions match
`plans/v0.0.5/canary-corpus.md` pins:

| Repository | Revision | Files scanned | Findings |
|---|---|---:|---:|
| gopdfsuit | `26d71268937136036c3be1770c0f7bdd89f87dc6` | 78 | 0 |
| monsoon | `e0f1027cb0c256853b835d8e20d8d206a96e44ed` | 43 | 0 |
| go-retry | `d3eb50afd37a09a9c0606c218d0dbe06e29d1544` | 5 | 0 |
| gorl | `ec54aaf15ce4d0f3f8014eac2548986c91d0f001` | 28 | 0 |
| no-mistakes | `0a2c82f993b9467c5ab84992313dfd13b66830af` | 222 | 0 |
| **Total** | | **376** | **0** |

Paths: `/home/chinmay/ChinmayPersonalProjects/gopdfsuit`; main-repo
`/home/chinmay/ChinmayPersonalProjects/codehound/real-repos/{monsoon,go-retry,gorl,no-mistakes}`
(worktree has no local `real-repos/`).

Zero useful hits ⇒ fixture-only quarantine is consistent with prior museum families.

---

## Integration

This branch targets `master` for review visibility. When an epic integration branch exists for
v0.0.6 residuals, prefer merging the integration PR to avoid double-merge. Shared maturity /
NEEDLES / audit edits remain integrator-owned per §0.2.

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | None |
| **Memory** | None |
| **Behavior / correctness** | None in this PR (comments only) |
| **API / CLI** | None until maturity integration |
| **Dependencies** | None |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None in this PR | — |
| Post-integration fixture-only | Still available under `--profile all` / `--only` |

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/cwe/domains/general_security/lifecycle_and_integrity/plugins.rs` | Signal-freeze comments |
| `plans/v0.0.6/residual-lifecycle-integrity.md` | Checklist complete |
| `plans/v0.0.6/evidence-r7-lifecycle-integrity.md` | Evidence |
| `plans/v0.0.6/pr-r7-lifecycle-integrity.md` | This PR body |

---

## Test plan

- [x] Inventory + selection rationale recorded
- [x] Signal freeze + disposition table
- [x] `make lint` — fmt check + clippy clean
- [x] `cargo test --locked --test go_cwe_detector_fixtures` — passed
- [x] `make test` — passed (459)
- [x] Three-rule release canary — 0 findings / 376 files
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

- Closes #164
- Relates to #151
- Plan: `plans/v0.0.6/residual-lifecycle-integrity.md`
- Sibling B4 complete: #110 (`privilege_escalation/`)
- Deferred within seam: `lifecycle.rs`, `runtime_state.rs`

---

## PR metadata checklist

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`documentation`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.6/pr-r7-lifecycle-integrity.md`

---

## Follow-ups (out of scope)

- `lifecycle.rs` / `runtime_state.rs` bounded trust slices
- Integrator maturity / NEEDLES / audit ledger updates

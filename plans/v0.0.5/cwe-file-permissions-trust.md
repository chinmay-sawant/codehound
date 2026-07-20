# v0.0.5 — CWE File-Permissions Catalog Trust

> **Parent:** [`plans/v0.0.5/cwe-catalog-trust-audit.md`](./cwe-catalog-trust-audit.md) — §2.11 long-tail inventory → **§2.12 disposition**
> **Epic:** [#85](https://github.com/chinmay-sawant/codehound/issues/85)
> **Phase 4 issue:** [#89](https://github.com/chinmay-sawant/codehound/issues/89)
> **Status:** Phase 4 **docs closure complete** (2026-07-20) — §2.12 proposed dispositions recorded from master source review. Phase 2 maturity/detector code and Phase 3 canary **pending integration**; this branch is docs-only to avoid dual-editing `maturity.rs`.
> **Estimated effort:** 2–3 focused days (full epic); Phase 4 validation + audit closure done on this branch.

---

## Overview

Audit the access-control file-permission siblings as one bounded CWE trust tranche:
`CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-281`, and `CWE-921`.

These rules already have stdlib and framework fixtures and are implemented in
`src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs`.
The work is to establish whether each detector deserves its current default
**Heuristic** maturity, must be quarantined as **fixture-only**, or can meet the
existing **Structural** promotion bar. This is a catalog-honesty slice, not a
bulk rule expansion.

---

## Executive Summary

The likely risk is corpus-shaped evidence hidden behind production-shaped file
APIs: `os.WriteFile`, `os.MkdirAll`, `os.OpenFile`, and `os.Create`. The
existing detectors already use call facts for several sinks, but some still
depend on exact modes, source-index strings, or fixture-specific paths.

Success means every rule receives an evidence-backed disposition, no rule is
promoted solely because its fixtures fire, and the release binary is canaried
against the pinned real Go repositories. A rule may remain useful under
`--profile all` while being excluded from recommended/security packs. The
expected outcome is higher trust in the security catalog, not necessarily more
default findings.

### Final rule-by-rule disposition (proposed 2026-07-20)

| Rule | Disposition | Notes |
|---|---|---|
| CWE-276 | **fixture-only** | WriteFile `0666` + session path/`session_data`/`X-Session-Data` co-signals |
| CWE-277 | keep **Heuristic** | `Umask(0)` + `MkdirAll(..., 0777)` production-shaped; not structural |
| CWE-278 | **fixture-only** | exact corpus formula `os.FileMode(hdr.Mode)` in OpenFile mode arg (aligned Phase 2 [#90](https://github.com/chinmay-sawant/codehound/pull/90)) |
| CWE-279 | **fixture-only** | `ParseUint` co-presence + WriteFile `0777` |
| CWE-281 | **fixture-only** | `os.Create` + exact `io.Copy(out, in)` without `info.Mode()` |
| CWE-921 | **fixture-only** | `/tmp/integration.key` + `0644` corpus path |

**Canary totals:** pending integration canary (Phase 3).
**Code ownership:** Phase 2 PR [#90](https://github.com/chinmay-sawant/codehound/pull/90) applies `is_fixture_only` for 276/278/279/281/921; this Phase 4 branch does not edit `maturity.rs`.

Full evidence table: audit **§2.12**.

---

## Scope and guardrails

- [x] Keep the tranche limited to `CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-281`, and `CWE-921`.
- [x] Do not bulk-label `source_index.rs`, bulk-change maturity, or promote a family from fixture evidence alone.
- [x] Keep existing fixture IDs and their vulnerable/safe oracle unless a new structural near-miss is necessary to prove a changed boundary.
- [x] Keep SourceIndex terms as impossibility or negative gates only; a retained literal must not be the primary reason a finding emits.
- [x] Preserve the existing rule IDs, report messages, profile semantics, and finding oracle unless a documented maturity decision requires a pack change.
- [x] Do not combine this tranche with BP-66+, typed Go facts, taint expansion, or unrelated CWE domains.

---

## Phase 1: Establish the frozen evidence baseline

### 1.1 Read the current detector and metadata surfaces

- [x] Record each rule's current sink/API, primary matching signal, SourceIndex dependencies, negative conditions, and finding-span source.
- [x] Confirm metadata, registry, rule documentation, and default-pack membership for all six IDs.
- [x] Run the focused fixture oracle before any edit:

  ```sh
  cargo test --locked --test go_cwe_detector_fixtures
  ```

- [x] Record the exact release-binary finding multiset for the six-rule `--only` selection before detector changes. *(Baseline = master detectors; no detector edits on Phase 4 branch.)*

### 1.2 Build the per-rule evidence table

- [x] `CWE-276`: distinguish the `os.WriteFile(..., 0666)` sink from the session-specific `sessions` / `session_data` / `X-Session-Data` co-signals. → **fixture-only candidate**
- [x] `CWE-277`: distinguish a generalized `syscall.Umask(0)` plus `os.MkdirAll(..., 0777)` condition from fixture-shaped ordering or path assumptions. → **keep Heuristic**
- [x] `CWE-278`: assess whether archive-entry mode propagation can be expressed from `os.OpenFile` call facts and archive metadata without requiring exact `hdr.Mode` text. → **fixture-only candidate** (exact `os.FileMode(hdr.Mode)` formula; Phase 2 #90)
- [x] `CWE-279`: assess whether `strconv.ParseUint` plus a hard-coded `0777` write proves a meaningful security boundary, rather than merely coexisting in the same file. → **fixture-only candidate**
- [x] `CWE-281`: assess whether `os.Create` plus `io.Copy` without source-mode preservation can be proven from call facts/AST shape without generic backup-tool false positives. → **fixture-only candidate** (`io.Copy(out, in)` names)
- [x] `CWE-921`: identify every corpus literal (`/tmp/integration.key`, `0644`, `APP_SECRET_DIR`) and determine whether a general sensitive-key classification exists today. → **fixture-only candidate**
- [x] Record each result as one of: `structural candidate`, `keep Heuristic`, or `fixture-only candidate`, with the concrete evidence and known false-positive boundary. *(No structural candidates.)*

---

## Phase 2: Apply only oracle-safe detector tightening

> **Ownership:** Phase 2 PR under epic #85. **Not landed on this Phase 4 branch.** Proposed outcomes below for integration.

### 2.1 Call-facts and SourceIndex hygiene

- [ ] For each rule whose primary match is currently text/needle-led, first determine whether existing `call_facts` provide a complete API, argument, and span signal. *(Source review: 276/277/278/279/281 already call-facts primary on sinks; 921 remains SI-primary museum — no rewrite strengthens proof.)*
- [ ] Where call facts are sufficient, make them the primary emitter and retain SourceIndex only as a cheap impossibility or negative prefilter. *(No mandatory rewrite on master; skip consistency-only edits.)*
- [ ] Do not rewrite `CWE-276`, `CWE-277`, `CWE-278`, `CWE-279`, `CWE-281`, or `CWE-921` merely for consistency; skip the code change when it does not strengthen the proof boundary.
- [ ] Label only the needles owned by this family as `negative-gate` or `fixture-literal`, with a comment naming the rule and rationale. *(Phase 2 optional hygiene.)*
- [ ] Add a named vulnerable/safe or renamed-near-miss fixture only when the revised structural boundary needs a regression proof; otherwise preserve the current fixture set unchanged.

### 2.2 Per-rule disposition and maturity

- [ ] Promote to `Structural` only when the rule satisfies every requirement in `cwe-catalog-trust-audit.md` §1.3. **None promoted.**
- [ ] Keep a rule `Heuristic` when it uses a production-shaped API signal but lacks enough real-module evidence or a broad enough negative boundary for structural promotion. **CWE-277 only.**
- [ ] Add a rule to `is_fixture_only` when its finding still depends on a corpus path, identifier, magic mode, exact fixture formula, or equivalent museum signal. **Proposed: CWE-276, CWE-278, CWE-279, CWE-281, CWE-921** (Phase 2 [#90](https://github.com/chinmay-sawant/codehound/pull/90)).
- [ ] Update `src/rules/maturity.rs` tests to assert every changed maturity and default-pack quarantine result. *(Phase 2 code on #90.)*
- [ ] Update rule documentation and metadata only when the observed evidence or user-visible profile eligibility changes.

---

## Phase 3: Canary and disposition gate

> **Ownership:** Phase 3 under epic #85. **Not run on this Phase 4 branch** (optional light canary OK; full three-repo record pending).

### 3.1 Build and scan the pinned real modules

- [ ] Build the release binary from the tranche branch:

  ```sh
  cargo build --release --locked
  ```

- [ ] Scan gopdfsuit, monsoon, and go-retry with the exact six-rule selection:

  ```sh
  target/release/codehound TARGET --profile all \
    --only CWE-276,CWE-277,CWE-278,CWE-279,CWE-281,CWE-921 \
    --format json --json-envelope --no-fail --no-cache
  ```

- [ ] Record repository revisions, file counts, findings by rule, and classifications: actionable, narrower-policy signal, false positive, or duplicate.
- [ ] Compare any candidate finding with the relevant existing owner before retaining it: taint CWE, PERF, BP, `go vet`, staticcheck, or a domain-specific tool.
- [ ] Freeze a keep/quarantine/narrow/delete decision for each rule. Zero hits alone is not a deletion or promotion signal.

### 3.2 Decision threshold

- [ ] Accept a maturity/profile change only when the fixture oracle, source review, and canary classifications agree.
- [ ] If a rule has no generalized evidence, quarantine it as fixture-only and preserve its fixtures as regression evidence.
- [ ] If a general rewrite would create an unknown false-positive budget, keep the current conservative detector and record the stronger proof requirement as deferred rather than widening it.
- [ ] Do not leave an undecided rule silently default-enabled; record an explicit disposition with its revisit condition.

**Canary status for Phase 4 docs:** **pending integration canary** (recorded in audit §2.12).

---

## Phase 4: Validation and documentation closure

### 4.1 Required checks

- [x] Run the focused fixture oracle after all edits:

  ```sh
  cargo test --locked --test go_cwe_detector_fixtures
  ```

- [x] Run maturity/profile tests for changed eligibility. *(No maturity.rs change on this branch; `cargo test --locked --lib rules::maturity` still green on master state.)*
- [x] Run `make lint` and `make test`.
- [x] Run `git diff --check`.
- [x] Confirm no unrelated rule IDs, profiles, or fixture manifest entries changed. *(Docs-only commit.)*

### 4.2 Record the outcome

- [x] Append a dated `§2.12` file-permissions sibling disposition to `plans/v0.0.5/cwe-catalog-trust-audit.md`.
- [x] Update this plan's checkboxes and status with the final rule-by-rule disposition and canary totals.
- [x] Update `plans/v0.0.5/cwe-catalog-trust-45.md` to point to this completed follow-on tranche, or explicitly record that a new scoped issue is required before code changes.
- [x] Update `plans/v0.0.5/pending-work.md` only if the issue ownership or active roadmap status changes; do not rewrite historical Phase 4 BP decisions. *(No ownership change — epic #85 already owns this tranche; pending-work left untouched.)*
- [x] Prepare a local commit only after all required checks pass; opening/pushing a PR remains a separate authorization step.

---

## Dependencies

- `src/lang/go/detectors/cwe/domains/access_control/file_permissions/file_modes.rs`
- `src/lang/go/detectors/cwe/source_index.rs`
- `src/rules/maturity.rs` and profile-pack tests
- Existing stdlib/framework fixtures and `tests/fixtures/manifest.toml`
- Release binary plus pinned gopdfsuit, monsoon, and go-retry canaries
- `plans/v0.0.5/cwe-catalog-trust-audit.md` §1.3 structural promotion bar; disposition §2.12

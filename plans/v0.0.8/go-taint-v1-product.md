# v0.0.8 — Go Taint v1 Product

> **Parent:** `plans/v0.0.8/README.md` — Go-only next phase (typed identity → cross-package taint → one precision lift)
> **Status:** Not started — live execution ledger; update rows only with code/test evidence
> **Estimated effort:** 2–4 weeks

---

## Overview

Ship a Go-only product slice that makes `--taint` / `--profile security` catch
**multi-package same-module** flows. Do not mint more fixture-only CWEs, BP, or
PERF rules. Do not open Python or other languages.

**Baseline (code evidence, 2026-07-24 audit):**

| Seam | Location | Current state |
|------|----------|---------------|
| Package identity | `src/lang/go/detectors/cwe/taint/model.rs` (`PackageIdentity`) | dir + `package` clause only; comment: full import-path identity deferred |
| Import map | `src/lang/go/detectors/cwe/taint/extract/imports.rs` | built; ponytail: full wiring into cross-function analysis deferred |
| Finalize callee lookup | `src/lang/go/detectors/cwe/mod.rs` (`finalize`, ~L273–309) | same-package only; package-qualified external calls skipped |
| Typed facts | `src/lang/go/typed/{mod,session,load}.rs` | `go list -json` load + session; **no detector consumes** `package_path_for_file` |
| Taint core rules | `src/lang/go/detectors/cwe/taint/rules/` | CWE-22/78/79/89/90/91 |
| Security pack | `src/rules/pack.rs` (`SECURITY_PACK_RULES`) | 9 ids: taint core + CWE-41/59/93 |
| Unsupported flows | `UnsupportedFlowKind::{Channel, Goroutine}` | G5 v0 channel pairing only; goroutine hard-cut |
| Propagators | `src/lang/go/detectors/cwe/taint/graph_query/build.rs` | `json.Unmarshal`/`xml.Unmarshal` output args; `Decoder.Decode` deferred |

---

## Executive Summary

- **Problem:** Same-package taint is real; cross-package same-module taint is not. `--typed` is paid CLI/session surface with zero finding impact. Security pack cannot honestly grow without graph wins.
- **Solution:** (1) import-path identity on `PackageIdentity` / symbol keys, preferring typed facts when loaded; (2) resolve import-qualified callees via import map + project package index; (3) exactly one precision lift (propagators **or** one G5 slice); (4) pack/honesty only from proven fires.
- **Success criteria:**
  1. Multi-package Go fixture: source in package A, sink/helper in package B under one module → finding under `--taint` for at least one taint-core CWE.
  2. With `--typed`, identity uses import path when `go list` succeeds; without toolchain, tree-sitter path still same-package-correct (no crash, no cross-contaminate).
  3. Existing same-package tests (`tests/go_taint_integration.rs` and unit taint tests) stay green.
  4. `SECURITY_PACK_RULES` only gains ids with multi-file proof — or stays unchanged if no promotion is earned.
- **Trade-offs / open questions:**
  - Cross-module / vendor / replace directives: out of scope unless free with `go list`.
  - Method calls on imported types still need conservative receiver resolution (do not invent types).
  - Pick **one** Phase 3 lift before coding it; record choice in 3.0.

---

## Phase 1: Import-path package identity

### 1.0 Design lock

- [ ] Write a short identity contract in this file (or a sibling note linked here): when `--typed` Ready → prefer `go list` import path; when Off/Unavailable → keep dir+clause behavior; never invent import paths from path heuristics alone if that risks cross-contaminate.
- [ ] Confirm `TaintSymbolKey` / `PackageIdentity` equality sites that must change together (`model.rs`, finalize indexes in `cwe/mod.rs`, any tests asserting dir-only identity).

### 1.1 `PackageIdentity` carries optional import path

- [ ] Extend `PackageIdentity` in `src/lang/go/detectors/cwe/taint/model.rs` with an import-path field (or equivalent key component) that is stable for `Hash`/`Eq`.
- [ ] Keep `from_unit(path, source)` as the no-typed fallback (dir + clause); do not break existing unit tests in `model.rs`.
- [ ] Add constructor/helper that accepts optional import path from typed facts (e.g. `from_unit_with_import_path(...)`).
- [ ] Unit tests: two dirs with same package clause name but different import paths do **not** collide when import path is set; without import path, prior dir+clause behavior preserved.

### 1.2 Populate identity from typed session when available

- [ ] In project-unit assembly path (`GoCweScan` accumulate / `make_project_unit` in `src/lang/go/detectors/cwe/mod.rs`), resolve file → import path via `crate::lang::go::typed::package_path_for_file` when session active.
- [ ] Path matching: align unit display path / absolute path with typed map keys (canonicalization already in `TypedFacts::package_path_for_file`).
- [ ] When typed Off or miss: leave import path unset; same-package tests must still pass.
- [ ] Smoke: with a tiny go module fixture + `--typed`, assert identity import path is non-empty for at least one file when `go` is on PATH (skip or mark unavailable cleanly if no toolchain — match existing typed degrade pattern).

### 1.3 Index keys use full identity

- [ ] `decl_index`, `package_name_index`, `summary_index` in `finalize` use the extended identity (no bare-name cross-package merge when import paths differ).
- [ ] Re-validate `tests/go_taint_integration.rs::two_package_duplicate_callee_does_not_cross_contaminate` (and siblings) still pass.
- [ ] Proof command (record outcome when done): `cargo test -q --test go_taint_integration -- --nocapture` (or project-equivalent `make` target).

### 1.4 Phase 1 gate

- [ ] No public CLI change required beyond existing `--typed`.
- [ ] Document in this ledger: “typed identity wired; cross-package hops still Phase 2.”
- [ ] `make lint` + `make test` green before marking Phase 1 complete.

---

## Phase 2: Cross-package same-module taint hops

### 2.0 Scope lock

- [ ] In-scope: caller imports package B in the same module; call is `alias.Func(...)` or equivalent resolved via `import_map` values matching B’s import path identity.
- [ ] Out-of-scope: stdlib/external module bodies, dynamic `interface` dispatch, reflection, `go func` spawn (unless Phase 3 chooses goroutine).
- [ ] Out-of-scope: changing taint-core CWE set (still 22/78/79/89/90/91) unless a hop only works for a subset — document which CWEs are proven.

### 2.1 Project package index by import path

- [ ] During `finalize`, build `import_path → file_idx` / summary lookup (or extend `summary_index` keys) when identity has import path.
- [ ] Fallback when import path missing: keep current same-package-only resolution (dir+clause).
- [ ] Do not use a global set of import **aliases** across files (existing comment at `cwe/mod.rs` ~L268–271 must remain true).

### 2.2 Resolve import-qualified callees

- [ ] Today finalize skips package-qualified calls when prefix ∈ caller import aliases (`cwe/mod.rs` ~L289–295). Replace skip with resolve:
  1. map alias → full import path via per-unit `import_map`;
  2. look up callee summary in target package by import path + function name;
  3. if missing → continue (no finding; no panic).
- [ ] Wire `build_import_map` into this path as the alias→path source (remove or update the ponytail “deferred wiring” comment in `imports.rs` only after call sites use it).
- [ ] Method calls: only resolve when prefix is an **import alias**, not a receiver variable (preserve current heuristic; do not claim type inference).

### 2.3 Multi-package fixture + integration test

- [ ] Add Go multi-package fixture under existing fixture layout (vulnerable + safe), module-local packages e.g. `pkg/a` source → `pkg/b` sink helper (or reverse: helper returns tainted → sink in caller).
- [ ] Integration test: analyzer with taint on finds ≥1 taint-core rule on vulnerable layout; safe layout silent.
- [ ] Integration test: duplicate bare function names in two packages still do not cross-contaminate (extend existing two-package test if needed).
- [ ] Optional: same vulnerable layout with `--typed` vs without — both must find when import map alone is enough; typed must not regress.

### 2.4 Cache / accumulate contract

- [ ] Confirm `requires_cache_state` / `accumulate_state` still correct when taint on (project units must include import maps + identity for all packages in the hop).
- [ ] Cache hit path rebuilds non-taint state as today; taint project state still accumulated when enabled (`engine_embedder_seams` expectations stay valid).

### 2.5 Phase 2 gate

- [ ] Proof: multi-package vulnerable fixture fires; safe silent; same-package suite green.
- [ ] Record exact test command + pass in this file when checked.
- [ ] `make lint` + `make test` green before marking Phase 2 complete.

---

## Phase 3: One precision ceiling lift

### 3.0 Choose exactly one lift (check one)

- [ ] **Option A — Known propagators:** extend `tainted_output_args` / `is_known_propagator` in `src/lang/go/detectors/cwe/taint/graph_query/build.rs` (e.g. `(*json.Decoder).Decode` / high-traffic stdlib) with fixtures proving path; update ponytail comments.
- [ ] **Option B — Channel G5 v1 slice:** one additional supported channel shape beyond same-function single send+recv (document which FN cases remain `UnsupportedFlowKind::Channel`).
- [ ] **Option C — Goroutine handoff v0:** track taint into a **direct** `go f(x)` argument into `f`’s param only (no select/channel mix); remaining goroutine shapes stay unsupported.

**Decision (fill when starting Phase 3):** `_none yet_` — owner: `_`

### 3.1 Implement chosen lift only

- [ ] Implement Option _ only; leave the other two unchecked as `[~]` deferred with pointer to this decision.
- [ ] Unit tests in `src/lang/go/detectors/cwe/taint/graph_query/tests.rs` (or extract tests) for the new shape.
- [ ] At least one end-to-end taint rule test (fixture or integration) showing a previously missed path now fires **or** a false-positive guard for the new edge.

### 3.2 Explicit non-goals remain deferred

- [~] Full select multi-send channel model — deferred until after Option B product need; see `UnsupportedFlowKind::Channel` tests.
- [~] Cross-goroutine channel IP-010 quarantine lift — deferred; see graph_query tests `channel_cross_goroutine_*`.
- [~] Builtin summary table (`lazy_static BUILTIN_SUMMARIES`) — deferred until opaque-call heuristic fails measured cases (`build.rs` ponytail).

### 3.3 Phase 3 gate

- [ ] Decision recorded; only one option implemented.
- [ ] `make lint` + `make test` green.

---

## Phase 4: Security pack + catalog honesty

### 4.1 Pack membership

- [ ] Review `SECURITY_PACK_RULES` / `TAINT_CORE_CWE_RULES` in `src/rules/pack.rs` after Phase 2–3.
- [ ] Add a rule id to security pack **only** if: maturity allows default packs (`src/rules/maturity.rs`) **and** multi-file or new-lift proof exists in this release.
- [ ] If nothing earns promotion: leave pack unchanged; note “no pack growth” here as intentional.

### 4.2 Maturity / quarantine honesty

- [ ] Do **not** add new `FixtureOnly` CWEs in this release.
- [ ] If a structural CWE starts depending on cross-package hops, add/adjust maturity only with evidence; update `maturity_for` / explain strings if needed (`src/rules/maturity.rs`, `src/rules/explain.rs`).
- [ ] `codehound rules --explain CWE-89` (and any newly packed id) still reports correct maturity/quarantine.

### 4.3 Recommended profile stability

- [ ] `ScanProfile::Recommended` still: S-tier PERF + taint-core CWEs; BP off (`src/core/profile.rs`).
- [ ] No accidental enable of BP or full catalog in default path.
- [ ] Profile unit tests in `src/core/profile.rs` remain green.

### 4.4 Phase 4 gate

- [ ] Pack diff reviewed in this ledger (list added/removed ids or “none”).
- [ ] `make lint` + `make test` green.

---

## Phase 5: Closure

### 5.1 Regression suite

- [ ] `make lint` — record date + result.
- [ ] `make test` — record date + result.
- [ ] Focused: `cargo test -q --test go_taint_integration`
- [ ] Focused: typed tests under `src/lang/go/typed/` (and any new typed+taint tests).
- [ ] Optional: `cargo bench --bench taint_graph` only if finalize path got heavier — not required for phase complete unless wall time regresses in CI.

### 5.2 Ledger hygiene

- [ ] All Phase 1–4 ship rows are `[x]` or intentional `[~]` with reason.
- [ ] No duplicate active work in older plans: if a v0.0.6/v0.0.5 row covered the same item, mark that older row `[~]` with pointer to `plans/v0.0.8/go-taint-v1-product.md` (only when touching those files).
- [ ] README phase map status updated to “Phase N complete / next unchecked”.

### 5.3 Handoff blurb (fill at end)

```
Result: _
Next unchecked: _
Proof commands: make lint (_); make test (_)
```

---

## Dependencies

| Dependency | Role |
|------------|------|
| `src/lang/go/typed/*` | Optional import-path facts via `go list` |
| `src/lang/go/detectors/cwe/taint/*` | Graph, import map, summaries, unsupported flows |
| `src/lang/go/detectors/cwe/mod.rs` | `GoCweScan` accumulate + finalize |
| `src/rules/pack.rs` | Security / taint-core allow-lists |
| `src/rules/maturity.rs` | Pack eligibility honesty |
| `src/core/profile.rs` | Recommended/security profile behavior |
| `tests/go_taint_integration.rs` | Cross-file / package taint proof |
| Go toolchain | Required only for `--typed` Ready path; degrade must stay safe |

### Explicit non-goals (entire v0.0.8)

- [~] Python or third language plugin work — out of scope (Go-only phase).
- [~] New BP/PERF long-tail rules — out of scope.
- [~] LSP / daemon / autofix — no seams; out of scope.
- [~] Broad G5 channel+select+goroutine productization — only the single Phase 3 choice.
- [~] Fixture-only CWE catalog expansion — forbidden this release.

---

## Status legend

| Mark | Meaning |
|------|---------|
| `[ ]` | Not started or not proven |
| `[x]` | Implemented and validated with current evidence |
| `[~]` | Intentionally deferred/partial — reason required |

**Update rule:** check a row only after the matching source change and the smallest relevant test/command succeed. For any non-doc code change closing a phase: `make lint` and `make test` must pass; record both at the phase gate.

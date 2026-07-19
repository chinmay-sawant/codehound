## Summary

Scope Go bad-practice project facts (project/server snapshots, package-doc
snapshots, go.mod and import maps) to a single top-level scan. Caches still
memoize within a scan for cold-scan performance, but are cleared through the
normal `reset_state` lifecycle so a same-`Analyzer` rescan always sees current
filesystem state.

---

## Motivation / context

- Plan: `plans/v0.0.5/rust-architecture-review.md` §2.1
- Issues: see **Related issues**
- Process-global `OnceLock<Mutex<HashMap<...>>>` BP caches retained data for
  process lifetime, built filesystem snapshots under the mutex, and contradicted
  the detector contract that project state is scan-scoped.

---

## Changes

### Go BP project facts

- `common.rs`: build project snapshots **off-lock**, short double-checked insert
  under the mutex; add `clear_project_snapshots()`.
- `code_organization.rs`: same pattern for package-doc snapshots; add
  `clear_package_doc_snapshots()`.
- `dependency_hygiene.rs`: same pattern for go.mod and project-import caches;
  add `clear_dependency_hygiene_caches()`.
- `GoBadPracticeScan::reset_state` clears all three fact groups (engine already
  calls this via `DetectorStateGuard` before/after each top-level scan).

### Tests

- Same-`Analyzer` integration regression: safe root → mutate `go.mod` +
  `main.go` → rescan asserts BP-41 / BP-47 / BP-50 / BP-54 / BP-55 / BP-57 /
  BP-59 fire with refreshed project facts.

---

## Code snippets

### Before (build under lock, process-lifetime retention)

```rust
fn project_snapshot_for_root(root: &Path) -> ProjectSnapshot {
    let mut guard = snapshot_cache().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(root) {
        return cached.clone();
    }
    let built = build_project_snapshot(root); // WalkDir while holding mutex
    guard.insert(root.to_path_buf(), built.clone());
    built
}
// no reset_state on GoBadPracticeScan
```

### After (off-lock build + scan-boundary clear)

```rust
fn project_snapshot_for_root(root: &Path) -> ProjectSnapshot {
    // short read under lock → build off-lock → short double-checked insert
}
fn reset_state(&self) {
    common::clear_project_snapshots();
    rules::clear_package_doc_snapshots();
    rules::clear_dependency_hygiene_caches();
}
```

---

## Impact

| Area | Impact |
|------|--------|
| **Performance** | Cold-scan path preserved: still one WalkDir per root per scan via prewarm + memoization. Snapshots no longer hold the mutex during filesystem work. |
| **Memory** | Snapshots cleared at scan end; independent roots no longer accumulate permanent process-global entries. |
| **Behavior / correctness** | Same-`Analyzer` rescan of a mutated root now refreshes BP project findings. |
| **API / CLI** | None |
| **Dependencies** | None |
| **Binary size / build time** | Negligible |

---

## Breaking changes / migration

| Item | Migration |
|------|-----------|
| None | — |

---

## Architecture notes

```mermaid
flowchart LR
  A[analyze_paths] --> B[reset_state clear BP caches]
  B --> C[prewarm project snapshot]
  C --> D[parallel file detectors]
  D --> E[memoized snapshots within scan]
  E --> F[DetectorStateGuard drop]
  F --> G[reset_state clear BP caches]
```

Caches remain process-static for minimal change (no detector-trait rewrite —
that is §2.4). Lifetime is scan-scoped via clear-on-reset.

---

## Files changed (high level)

| Path | Change |
|------|--------|
| `src/lang/go/detectors/bad_practices/common.rs` | Off-lock build + clear for project snapshots |
| `src/lang/go/detectors/bad_practices/rules/code_organization.rs` | Off-lock build + clear for package-doc snapshots |
| `src/lang/go/detectors/bad_practices/rules/dependency_hygiene.rs` | Off-lock build + clear for go.mod / imports |
| `src/lang/go/detectors/bad_practices/mod.rs` | `reset_state` clears all BP project facts |
| `tests/go_bad_practice_project_integration.rs` | Same-Analyzer rescan regression |
| `plans/v0.0.5/pr-arch-bp-scan-scoped.md` | Filled PR body |

---

## Test plan

- [x] `make lint` — pass (`cargo clippy ... -D warnings` + `cargo fmt --check`)
- [x] `cargo test --locked --test go_bad_practice_integration` — 16 passed
- [x] `cargo test --locked --test go_bad_practice_project_integration` — 3 passed (incl. rescan)
- [x] `make test` — 412 passed, 0 failed (nextest)

### Commands

```sh
make lint
cargo test --locked --test go_bad_practice_integration -- --nocapture
cargo test --locked --test go_bad_practice_project_integration -- --nocapture
make test
```

---

## Related issues

- Closes #57
- Relates to #56

---

## Integration

This branch is intended to also merge into the epic #56 integration branch for
combined validation when that workstream is assembled.

---

## PR metadata checklist (author)

- [x] Self-assigned (`--assignee @me`)
- [x] Labels applied (`bug`, `enhancement`)
- [x] Related issues filled with real ticket IDs
- [x] Filled body committed under `plans/v0.0.5/pr-arch-bp-scan-scoped.md`

---

## Follow-ups (out of scope)

- §2.2 Qualify same-package taint symbols
- §2.3 Remove Go-shaped inputs from the generic language-plugin seam
- §2.4 Explicit per-scan detector session / generic prepare-project hook
  (would remove remaining process-static caches entirely)

---

## Reviewer checklist

- [ ] Behavior matches summary and test plan
- [ ] No unrelated changes in diff
- [ ] Public API / CLI changes documented
- [ ] New rules have fixture coverage in `tests/fixtures/`
- [ ] PR has assignee and labels
- [ ] Related issues use correct Closes/Relates keywords
- [ ] No secrets or generated artifacts committed

---

## Release notes (if user-facing)

fix(go): BP project-level findings refresh correctly on same-Analyzer rescan after project file changes.

# fix(taint): qualify same-package taint symbols by package identity

## Summary

Inter-procedural CWE finalization no longer indexes functions and summaries by
bare name alone. Declarations and summaries are keyed by **package identity +
receiver type + function name**, and unqualified callees resolve only inside the
caller's package. Duplicate bare names in separate packages can no longer create
false inter-procedural findings.

Closes #58. Relates to #56 (epic). Implements
`plans/v0.0.5/rust-architecture-review.md` §2.2.

---

## Motivation / context

Taint advertises **same-package** inter-procedural summaries, but
`GoCweScan::finalize` indexed `func_to_file` and `summary_index` with bare
`String` names and fell back from raw callee to bare callee across the whole
project. Two packages both defining `openPath` could therefore share a sink
summary: a safe package inherited a sink from an unrelated package.

Import extraction already deferred full cross-package wiring; this change makes
resolution honesty match that boundary.

---

## Changes

### Symbol keys (`taint/model.rs`)

- Add `PackageIdentity` (parent directory of the unit path + `package` clause).
- Add `TaintSymbolKey` (`package` + optional normalized receiver type + name).
- Helpers: `package_clause_name`, `normalize_receiver_type`.

### Finalize resolution (`cwe/mod.rs`)

- Store `package` on each `ProjectUnit`.
- Replace bare-name `func_to_file` / `summary_index` with package-qualified
  `TaintSymbolKey` maps plus a same-package bare-name secondary index for
  method calls when the receiver type is unknown at the site.
- Skip import-aliased package-qualified calls using the **caller's** import map
  only (not a project-wide prefix set).
- `find_same_package_summary` refuses cross-package bare-name matches.

### Fixtures / tests

- `tests/fixtures/go/taint_projects/package-dup-callee-safe` — packages `bad`
  and `good` both define `openPath`; only `bad` is a sink. Scanning both
  together must emit **no** CWE-22 (safe package must not inherit the sink).
- `tests/fixtures/go/taint_projects/package-dup-callee-vulnerable` — same-package
  sink still fires when another package defines the same bare name without a sink.
- Integration coverage in `tests/go_taint_integration.rs`.
- Unit tests for package identity and symbol key uniqueness.

### Docs

- `documents/taint.md`: inter-procedural limitation clarified as same-package
  only, keyed by package + receiver + name.

### Out of scope (unchanged)

- BP global caches / scan-scoped facts (#57).
- Plugin `extract_deps` API / engine lifecycle redesign (#59).
- Full import-path cross-package taint wiring.

---

## Code snippets

### Package-qualified key

```rust
pub struct PackageIdentity {
    pub dir: SharedText,  // parent dir of unit path
    pub name: SharedText, // package clause
}

pub struct TaintSymbolKey {
    pub package: PackageIdentity,
    pub receiver: Option<SharedText>, // normalized (*Handler, …)
    pub name: SharedText,
}
```

### Same-package lookup (finalize)

```rust
// Unqualified / method bare names resolve only in caller_package.
let callee_summary = find_same_package_summary(
    &per_file, &summary_index, &package_name_index, &decl_index,
    &unit.package, raw_callee, &callee_name, site.is_method_call,
);
```

---

## Impact

| Area | Impact |
|------|--------|
| **Correctness** | Eliminates cross-package bare-name contamination of inter-procedural CWE summaries |
| **Same-package behavior** | Preserved for existing single-package IP fixtures |
| **Performance** | Negligible; slightly richer hash keys at finalize only |
| **API / engine** | No detector trait, BP cache, or plugin API changes |

---

## Test plan

```sh
make lint
cargo test --locked --test go_taint_integration
cargo test --locked --test go_cwe_detector_fixtures
make test
```

Observed:

- `make lint` — pass
- `go_taint_integration` — 3/3 pass (including two-package fixture)
- `go_cwe_detector_fixtures` — 4/4 pass
- `make test` — 419/420; only pre-existing flake
  `engine_baseline_io::large_baseline_loads_and_filters_under_target` under
  parallel nextest load (~2.05–2.19s vs &lt;2s budget). Same test passes in
  isolation (~1.3s). Unrelated to this change.

---

## Related issues

- Closes #58
- Relates to #56
- Plan: `plans/v0.0.5/rust-architecture-review.md` §2.2

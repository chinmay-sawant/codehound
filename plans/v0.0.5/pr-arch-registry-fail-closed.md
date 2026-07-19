# fix(engine): fail closed if built-in registry materialization breaks

## Summary

Make built-in language-plugin registry construction fail closed: a materialization
or validation error on the production path aborts instead of logging and returning
an empty registry that could report a successful no-detector scan.

## Motivation / context

Architecture review §5.3 (issue #78, relates to #75): `Registry::from_plugins`
logged a composition failure then handed out an empty `Registry`. Default analyzer
construction (`Registry::default` → CLI and library happy path) could therefore
complete a scan with zero detectors and zero findings after a packaging invariant
was broken.

Plan: `plans/v0.0.5/rust-architecture-review.md` §5.3

## Changes

### Production registry path

- `Registry::from_plugins` (used by `Registry::default`) no longer log-and-return
  an empty registry on `materialize_plugins` failure.
- On validation failure it **panics** with a clear message, documenting that
  built-in composition is an invariant and refusing to start empty.
- Embedder path `Registry::with_plugins` is unchanged: still returns typed
  `RegistryError` (`DuplicateLanguage`, `DuplicateExtension`,
  `DetectorLanguageMismatch`).

### Tests

- `from_plugins_fails_closed_on_composition_error` — forced duplicate-language
  materialization via the production path must panic (no empty registry).
- `default_registry_materializes_built_in_plugins` — happy path still registers
  detectors and languages.
- `empty_registry_allows_successful_zero_finding_scan` — documents the hazard
  (empty is a valid *explicit* composition) and proves composition errors return
  `Err` rather than `Ok(empty)`.

## Code snippets

### Before

```rust
match materialize_plugins(plugins) {
    Ok(prepared) => Self::from_prepared(prepared),
    Err(err) => {
        tracing::error!(error = %err, "built-in language plugin materialization failed");
        Self { /* empty maps */ }
    }
}
```

### After

```rust
match materialize_plugins(plugins) {
    Ok(prepared) => Self::from_prepared(prepared),
    Err(err) => {
        panic!(
            "built-in language plugin materialization failed ({err}); \
             refusing to start with an empty registry"
        );
    }
}
```

## Out of scope

- BP process-global cache ownership (#57 / plan §5.2)
- Taint same-package method receiver resolution (plan §5.1)
- Changing `AnalyzerBuilder::build` / public `Default` to a fallible API
  (abort-before-scan satisfies the fail-closed requirement without API churn)
- Mapping production failure into `Error::Config` exit codes (would require a
  fallible default construction surface)

## Test plan

- [x] `make lint`
- [x] `cargo test --locked --lib engine::registry`
- [x] `cargo test --locked --test engine_embedder_seams`
- [x] `make test`

## Related issues

- Closes #78
- Relates to #75

## Known interactions

- **Happy path:** `Registry::default()` / `Analyzer::builder().build()` still
  succeed with the built-in plugin set from `enabled_plugins()`.
- **Embedders:** custom plugins continue to use `with_plugins` → `Result`.
- **No BP/taint changes:** only the registry materialization error branch.

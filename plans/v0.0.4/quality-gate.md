# v0.0.4 — Quality Gate: `missing_docs` Zero-Warning Policy

> **Status:** Done  
> **Branch:** `feat/bp-implementations`  
> **Date:** 2026-07-16

---

## Problem

`make test` / `cargo test` emitted **~207** warnings of the form:

```text
warning: missing documentation for a struct field
```

Tests still **passed** (exit 0), but the output was noisy. Root cause was an intentional lint carve-out in `src/lib.rs`:

```rust
// OLD — documentation debt only warned outside Clippy
#![cfg_attr(not(clippy), warn(missing_docs))]
```

Effects of that gate:

| Command | `missing_docs` behavior |
|---------|-------------------------|
| `cargo test` / `cargo build` | **warn** → 207 warnings printed |
| `make lint` (`cargo clippy … -D warnings`) | **off** (because `clippy` cfg) → lint looked clean |

So the suite could “pass” while still shipping public API without docs, and Clippy never enforced the debt.

---

## Fix

### 1. Remove the Clippy avoidance

```rust
// NEW — always warn; `make lint` turns warnings into errors via `-D warnings`
#![warn(missing_docs)]
```

Comment documents that `make lint` ratchets this to an error under Clippy.

### 2. Document the public surface

Added `///` docs on previously undocumented public items across **~40 files**, including:

| Area | Examples |
|------|----------|
| CLI | `Cli`, `Command`, `LangMode`, `OutputFormat`, `RuleCategory`, `SeverityArgs` |
| Core | `ScanContext`, `FailPolicy`, `LanguageId`, `LanguagePlugin`, `Detector`, `ParsedUnit` |
| Engine | config types, cache types, baseline, registry, diagnostics, walk entries |
| Errors / fixtures | `Error` / `IoOp` variants & fields, `FixtureError`, `TextFixture` |
| Reporting / export | `TextOptions`, reporters, `ExportOptions` / `ExportSummary` |
| Lang helpers | `SourceIndex` methods, Go sink tables, plugin macro-generated structs |

### 3. Gates re-verified

| Gate | Result |
|------|--------|
| `make lint` | **exit 0** (clippy `-D warnings` + `fmt --check`) |
| `cargo test --no-run` | **0** `missing documentation` warnings |
| `cargo check --lib --all-features` | **0** `missing documentation` warnings |

---

## Checklist (completed)

- [x] Identify why test output warned but lint stayed green
- [x] Remove `cfg_attr(not(clippy), …)` carve-out
- [x] Enable `#![warn(missing_docs)]` for all builds
- [x] Document all public items that triggered warnings (~207)
- [x] Cover `cfg(test)` public statics under clippy `--all-targets`
- [x] `make lint` clean
- [x] No remaining `missing documentation` warnings on test compile
- [x] Commit the change set

---

## Policy going forward

- Public items **must** have rustdoc comments.
- `make lint` fails the build if any `missing_docs` warning appears (`-D warnings`).
- Do **not** reintroduce `cfg_attr(not(clippy), …)` for documentation lints.
- Prefer documenting fields/variants/methods next to the type they belong to; keep comments short and factual.

---

## Related

- Cold-scan performance plan (separate workstream): [`cold-scan-performance.md`](./cold-scan-performance.md)
- Overview: [`README.md`](./README.md)

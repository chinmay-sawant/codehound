# v0.0.6 — G4 Typed Go / go/packages

> **Class:** A (gated)  
> **Issue:** [#155](https://github.com/chinmay-sawant/codehound/issues/155) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)
> **Parent:** [`pending-work.md`](./pending-work.md)  
> **Prior evidence:** [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md)  
> **Gate A package:** [`evidence-g4-gate-a.md`](./evidence-g4-gate-a.md)  
> **Status:** Gate A **PASS** · **impl tranche 1** — package facts via `go list` behind `--typed`

## Checklist

### Gate A (all required)
- [x] A1–A6 — see evidence-g4-gate-a.md

### Implementation
- [x] Optional fact layer behind explicit flag (`--typed` / `[codehound.typed]`)
- [x] Tree-sitter remains primary default
- [x] Degrade when Go missing / `go list` fails
- [x] Session API: `package_path_for_file` / `TypedLoadStatus`
- [x] Tests: `tests/go_typed_facts.rs`
- [ ] Future: `go/types` expression typing + pilot rule precision (not this tranche)

### Explicit non-goals
- [x] No required typed mode for offline/recommended scans
- [x] No Cargo dependency on Go toolchain crates
- [x] No recommended-pack membership change

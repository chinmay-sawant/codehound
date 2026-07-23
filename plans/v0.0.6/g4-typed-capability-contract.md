# G4 — Typed Go facts FN/FP capability contract

> **Gate:** A3 · Issue [#155](https://github.com/chinmay-sawant/codehound/issues/155)  
> **Parent evidence:** [`evidence-g4-gate-a.md`](./evidence-g4-gate-a.md)  
> **Status:** Accepted 2026-07-23 (docs)

---

## Purpose

Bound what an **optional** typed fact layer may claim. Prefer honest FN over fake precision.

---

## In scope (may improve precision)

| Capability | Example rule benefit | FP control |
|------------|----------------------|------------|
| Concrete receiver / named type of selector | Method on `*os.File` vs interface guess | Only when `types.Info` resolves; else tree-sitter path |
| Same-package function signatures | Arity / type of args at call | Same-package load only unless imports fully typed |
| Build-tag file set | Skip wrong-OS files when tags match load | Document tag defaults (`GOOS`/`GOARCH` of host) |
| Package path identity | Distinguish std vs third-party same name | From `packages.Package.PkgPath` |

---

## Out of scope (explicit FN — do not fake)

| Ceiling | Owner |
|---------|--------|
| Channel send/recv dataflow | G5 / taint ceiling |
| Goroutine happens-before | G5 |
| External-package taint summaries without designed edges | G5 |
| Whole-program security-grade taint | ROADMAP non-goal |
| FO museum → Structural via types alone | Catalog §1.3 |
| Offline / no-`go` environments | Tree-sitter only |

---

## FP risks (must mitigate)

1. **Partial load / errors:** treat as missing facts; **no** speculative types.
2. **Wrong build tags:** may miss files or see wrong files — document host tags; never claim complete multi-OS proof.
3. **Vendoring / GOPROXY failures:** degrade; surface diagnostic when typed requested.
4. **Interface method sets incomplete:** do not emit “typed-proved safe” without full method set.

---

## Non-goals

- Parallel typed-only rule catalog
- Recommended pack requiring typed
- Replacing tree-sitter parse pipeline

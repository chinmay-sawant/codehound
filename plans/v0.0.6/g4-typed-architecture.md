# G4 — Optional typed fact layer architecture (accepted)

> **Gate:** A4 · Issue [#155](https://github.com/chinmay-sawant/codehound/issues/155)  
> **Status:** **Accepted** 2026-07-23 (design) — implementation not in this doc  
> **Promotes:** draft in [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md) § Minimal design sketch

---

## Goals

- Optional precision for rules that guess from selectors / names.
- Same rule IDs and finding construction as tree-sitter mode.
- Default + recommended scans: **offline**, **no Go toolchain**, tree-sitter-only.

---

## Non-goals

- Security-grade whole-program taint
- Typed required for release / CI recommended gate / pack membership
- Replacing tree-sitter as primary unit pipeline
- Solving channel/goroutine DF “via types” (G5)

---

## Layering

```
Scan request
  ├─ always: walk → tree-sitter parse → ParsedUnit → facts → Detector::run
  └─ only if typed enabled AND toolchain available:
       go/packages load (once/session) → go/types info
       → TypedFactProvider (query API)
       → detectors optionally consult provider
          (missing ⇒ identical to tree-sitter-only)
```

---

## API principles

1. **Tree-sitter primary** — `Detector::run` keeps current inputs.
2. **Optional side channel** — context field / trait object; never sole emit path.
3. **Degrade gracefully** — load failure ⇒ tree-sitter-only + diagnostic.
4. **Same rules** — no typed-only catalog for 0.1.x.
5. **Session lifecycle** — load package graph once per scan (`begin_scan`).

---

## Product / CLI (future implementation)

| Surface | Rule |
|---------|------|
| Flag / config | Opt-in only (e.g. `--typed` or `[analysis] typed = true`) |
| Default | off |
| Recommended pack | must not require typed |
| Docs | cost table from A5 + toolchain requirement |

---

## Coordination with G5

G5 may **consume** typed facts after this architecture ships. G5 must not implement a shadow typed mode under a taint ticket.

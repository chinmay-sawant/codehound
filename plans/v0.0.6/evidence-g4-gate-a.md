# Evidence — G4 Gate A (A1–A6) reopen package

> **Issue:** [#155](https://github.com/chinmay-sawant/codehound/issues/155) · Epic [#151](https://github.com/chinmay-sawant/codehound/issues/151)  
> **Prior eval:** [`../v0.0.5/phase5-g4-typed-go-gate-eval.md`](../v0.0.5/phase5-g4-typed-go-gate-eval.md) (2026-07-22 — remain deferred)  
> **Date:** 2026-07-23  
> **Branch:** `chore/g4-gate-a-package`  
> **Kind:** Docs + external cost probe only — **no** CodeHound `go/packages` integration, **no** `--typed` flag in product

---

## Executive decision

| Field | Value |
|-------|--------|
| **Gate A all pass?** | **Yes** (this package) |
| **Implement product typed mode in this PR?** | **No** |
| **Next** | New scoped implementation issue / tranche after merge (optional `TypedFactProvider` behind explicit flag) |
| **A6** | Held — typed never blocks release or recommended pack |

---

## A1 — PERF pack typed-mode readiness (PASS)

### Agreed external bar (named)

| Metric | Bar | Evidence 2026-07-23 |
|--------|-----|---------------------|
| Senior sample actionability | ≥ **95%** actionable on 20-row recommended sample | Pilot + P1: still **95%** ([`recommended-pack-pilot.md`](../v0.0.5/recommended-pack-pilot.md) §6) |
| Recommended multiset stability | Core 3-pin multiset **unchanged** vs 2026-07-21 after R1–R8 | P1: **41** core + 2 extended identical |
| Stop-the-line | No material FP family regression | **Not triggered** |
| Clean canary | `gorl` recommended **0** | Held |
| Cold scan | gopdfsuit class **under 1.0s** tree-sitter | ~0.50–0.87s |

### Product acceptance (recorded here)

**Accepted:** recommended / S-tier PERF on the pinned decision corpus meets the external bar above and is **sufficient foundation** to *consider* an **optional** typed mode. This does **not** put typed mode on the recommended pack or release critical path (A6).

**Not claimed:** typed mode improves PERF FP rate; PERF trust is a **precondition**, not a typed benefit proof.

---

## A2 — Catalog honesty boundary (PASS)

Typed facts must **not** paper over detector trust holes. Post R1–R8 + G3 residual FO:

| Class | Disposition | Typed role |
|-------|-------------|------------|
| FO museums (incl. auth_flows 305–309/620/836, 619/917, R1/R4–R7 sets) | **fixture-only** | **No** — maturity/quarantine owns honesty |
| CWE-201 / 213 | Heuristic keep (call_facts sinks) | Optional precision later; not required for honesty |
| CWE-277 | Heuristic keep; G2 Structural deferred (0 canary hits) | Typed does **not** unlock Structural without §1.3 |
| BP-66+ / BP-71 | G1 future — 0 actionable hits | Out of typed scope |
| §1.3 Structural bar | Unchanged | Typed never substitutes for real-module + renamed-negative proof |

**Ledger statement:** residual long-tail is either FO-quarantined, Heuristic-kept with written rationale, or gated (G1/G2/G5). Typed mode is scheduled only to improve **precision of already-honest rules**, not to flip FO → Structural or hide NEEDLES museums.

---

## A3 — FN/FP capability contract (PASS)

See [`g4-typed-capability-contract.md`](./g4-typed-capability-contract.md).

Summary:

| Improves (in scope) | Still unsupported (honest FN) |
|---------------------|-------------------------------|
| Receiver / concrete types behind interfaces (same module) | Channel / goroutine handoffs (G5) |
| Same-package signatures / overloads disambiguation | Whole-program security-grade taint |
| Build-tag–accurate file sets when toolchain loads tags | Cross-module summaries without package graph load |
| Fewer name-guess FPs on method selectors | Offline scans (no toolchain) — tree-sitter only |

**FP risk:** wrong/incomplete `packages.Load` → must **degrade to tree-sitter**, never invent types.

---

## A4 — Architecture sketch accepted (PASS)

See [`g4-typed-architecture.md`](./g4-typed-architecture.md).

Accepted principles:

1. Tree-sitter primary default (offline, no `go` required).
2. Optional typed side channel; same rule IDs; missing facts ⇒ tree-sitter behavior.
3. Recommended pack **must not** require typed.
4. Session-scoped load once per scan when enabled.

Draft sketch in phase5-g4 eval is **promoted** to accepted design for implementation planning.

---

## A5 — Cost measurements accepted (PASS)

### Method

- **Tree-sitter baseline:** release `codehound --profile recommended` on pinned repos (host 2026-07-23).
- **Typed probe (external only):** throwaway `packages.Load` with `NeedTypes|NeedTypesInfo|NeedSyntax` via `golang.org/x/tools/go/packages` — **not** linked into CodeHound. Go **1.23.0** at `/usr/local/go`.

### Results

| Target | TS wall (s) | TS RSS max (KB) | `packages.Load` wall (s) | Load RSS max (KB) | pkgs / go files | load errs |
|--------|------------:|----------------:|-------------------------:|------------------:|----------------:|----------:|
| go-retry | 0.03 | 8_640 | **14.9** | 221_220 | 1 / 5 | 1 |
| monsoon | 0.16 | 11_652 | **25.6** | 306_048 | 11 / 42 | 11 |
| gorl | 0.09 | 10_324 | **38.9** | **1_074_400** | 20 / 28 | 20 |
| gopdfsuit | ~0.5–0.9 (all profile class) | — | **43.9** | 217_664 | 19 / 67 | 18 |

**Order-of-magnitude:** typed load is **~100–400×** wall vs recommended tree-sitter scan on small modules; RSS can exceed **1 GB** (gorl).

### Product acceptance of cost

| Dimension | Acceptance |
|-----------|------------|
| Default / recommended | **Tree-sitter only** — typed cost is **not** acceptable on default path |
| Opt-in `--typed` (future) | Cost accepted **only** when user explicitly enables and has Go toolchain |
| CI | Optional job only; core `make test` stays no-Go-for-analysis |
| Offline | Preserved when typed off |
| Errors on load | Degrade; do not fail the scan hard on default profiles |

A5 is **pass for opt-in economics**, not pass for making typed cheap.

---

## A6 — Non-blocker policy (PASS — held)

Typed mode must not become a release or recommended-pack dependency. Reaffirmed.

---

## Explicit non-actions (this PR)

- No `--typed` CLI / config in product
- No Cargo deps for Go toolchain bridge
- No detector rewrites assuming types
- No recommended-pack membership change

---

## Reopen implementation path

1. Merge this Gate A package.
2. Open or use #155 implementation tranche: optional fact provider + one pilot rule max.
3. Keep A6 in every design review.
4. G5 must not smuggle typed mode under taint tickets.

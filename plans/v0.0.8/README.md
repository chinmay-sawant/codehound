# v0.0.8 — Go Taint v1 Product

> **Parent:** conversation synthesis (Go-only next phase) + live code in `src/lang/go/`
> **Status:** Not started — canonical execution ledger for the next Go-focused release slice
> **Estimated effort:** 2–4 weeks (one vertical: typed identity → cross-package taint → one precision lift)

---

## Overview

Engine, Go CWE/PERF/BP catalogs, same-package inter-procedural taint, optional
`--typed` (`go list`) load, and product packs are already in tree. This release
does **not** grow the fixture museum or open a second language. It makes Go
security taint product-grade across packages in one module.

Canonical ledger: [`go-taint-v1-product.md`](./go-taint-v1-product.md).

---

## Executive Summary

| Item | Detail |
|------|--------|
| Problem | Taint finalize is same-package only; `build_import_map` and `--typed` facts exist but do not drive callee resolution; security pack stays thin while ~89 CWEs are fixture-only |
| Solution | Wire import-path package identity (typed when available), resolve cross-package same-module calls, then one precision lift; expand security pack only from proven graph wins |
| Success | Multi-package fixture fires under `--taint`; `--typed` changes at least one resolution path (or documents no-op honestly); security pack stays small and high-signal |
| Non-goals | Python/other langs, more BP/PERF long-tail, LSP/autofix/daemon, broad G5 channel/select/goroutine before identity lands |

---

## Phase map

| Phase | Title | Depends on |
|-------|--------|------------|
| 1 | Import-path package identity | — |
| 2 | Cross-package same-module taint hops | Phase 1 |
| 3 | One precision ceiling lift | Phase 2 |
| 4 | Security pack + honesty gates | Phase 2–3 |
| 5 | Closure (`make lint` / `make test`) | Phase 1–4 |

---

## Dependencies

- Go toolchain on PATH for `--typed` load path (`src/lang/go/typed/load.rs`)
- Existing taint finalize in `src/lang/go/detectors/cwe/mod.rs`
- Existing import map in `src/lang/go/detectors/cwe/taint/extract/imports.rs`
- Existing typed session in `src/lang/go/typed/{mod,session,load}.rs`
- Pack constants in `src/rules/pack.rs` (`SECURITY_PACK_RULES`, `TAINT_CORE_CWE_RULES`)
- Integration tests under `tests/go_taint_integration.rs` and related taint fixtures

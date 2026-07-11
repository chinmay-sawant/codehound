# PERF rule tiers

Product policy for Go performance rules. Pack membership lives in
`src/core/profile.rs`; numeric tiers in `src/lang/go/detectors/perf/tiers.rs`.

| Tier | Severity | Profile | Meaning |
|------|----------|---------|---------|
| **S** | Medium | `recommended` + `perf` | Ship in CI — timeouts, body close, regex-in-loop, defer-in-loop, N+1 |
| **A** | Medium | `perf` | Framework / hot-path (sqlx, MaxBytesReader, cache bounds, …) |
| **B** | **Info** | `all` only | Micro-opts (`time.Since`, TrimPrefix, static `fmt.Errorf`, …) |
| **C** | **Info** | `all` only | Overlaps staticcheck / gocritic / prealloc — prefer those tools |

## S-tier (CI default)

`PERF-1`, `7`, `50`, `58`, `71`, `101`, `103`, `189`, `190`

## A-tier (`--profile perf`)

`PERF-11`, `12`, `22`, `31`, `82`, `85`, `142`, `143`, `164`, `183`, `210`, `213`

## B-tier micro-opts (info)

`PERF-15`, `17`, `18`, `19`, `35`, `42`, `120`, `122`, `127`, `146`, `157`, `188`

## C-tier (staticcheck-adjacent)

`PERF-2`, `3`, `4`, `6`, `16` — keep under `--profile all` for completeness; do not enable in CI if you already run prealloc/staticcheck.

## Framework coverage status

| Stack | Status |
|-------|--------|
| **net/http** | S-tier (timeouts, body close, client timeout) |
| **Gin** | S-tier body close + handler needles |
| **Echo** | Handler detection + existing sqlx/echo PERF rules |
| **Chi** | Request-path detection via `chi.URLParam` / router needles (Phase 2) |
| **Fiber** | Handler detection via `*fiber.Ctx` |
| **GORM / sqlx** | N+1, scan, named query rules |
| **gRPC / redis** | Partial (e.g. KEYS); expand later |

## Hot-path policy (Phase 2)

A site is hot when:

1. Inside a loop, or
2. Local window is handler-shaped (`ResponseWriter`, `*gin.Context`, `echo.Context`, `*fiber.Ctx`, `chi.URLParam`, …), or
3. Enclosing function name looks like `*Handler` / `*Middleware` / `ServeHTTP`

**Not** hot: bare `func (`, package-level init, `main`/`init`, broad names (`build`, `process`, `generate`).

## Real-world fixtures

Prefer multi-file / realistic packages under `tests/fixtures/go/perf_real_world/` for S-tier rules (see `http_server-*`). Synthetic `package sample` twins remain for unit inventory.

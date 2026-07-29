# PERF rule tiers

Product policy for Go performance rules.

| Source of truth | Location |
|-----------------|----------|
| S / A pack membership | `src/rules/pack.rs` (`PERF_TIER_S_*`, `PERF_TIER_A_*`) |
| B / C numeric lists + severity | `src/lang/go/detectors/perf/tiers.rs` |
| Profile wiring | `src/core/profile.rs` |

**PERF tiers ≠ maturity tags.** Tiers control pack membership and PERF severity.
Maturity (`heuristic`, `fixture-only`, …) is a separate axis — see
[rule-catalog.md](./rule-catalog.md).

| Tier | Severity | Profile | Meaning |
|------|----------|---------|---------|
| **S** | Medium | `recommended` + `perf` | Ship in CI surface — timeouts, body close, regex-in-loop, defer-in-loop, N+1 |
| **A** | Medium | `perf` | Framework / hot-path (sqlx, MaxBytesReader, cache bounds, …) |
| **B** | **Info** | `all` only | Micro-opts (`time.Since`, TrimPrefix, static `fmt.Errorf`, …) |
| **C** | **Info** | `all` only | Overlaps staticcheck / gocritic / prealloc — prefer those tools |
| **Unclassified** | Medium | `all` (default severity) | Not in S/A/B/C lists; still Medium so `--profile all` medium-as-errors can gate them |

Under `--profile recommended`, fail policy is **strict** (high+). S-tier PERF is
**medium**, so it is **visible but non-failing** unless you pass
`--warnings-as-errors`. See [go-recommended-pack.md](./go-recommended-pack.md).

---

## S-tier (CI default surface)

`PERF-1`, `7`, `50`, `58`, `71`, `101`, `103`, `189`, `190`

## A-tier (`--profile perf`)

`PERF-11`, `12`, `22`, `31`, `82`, `85`, `142`, `143`, `164`, `183`, `210`, `213`

## B-tier micro-opts (info)

`PERF-15`, `17`, `18`, `19`, `35`, `42`, `46`, `120`, `122`, `127`, `145`, `146`, `157`, `188`

## C-tier (staticcheck-adjacent)

`PERF-2`, `3`, `4`, `6`, `16` — keep under `--profile all` for completeness; do
not enable in CI if you already run prealloc/staticcheck.

---

## Worked examples (one per tier)

### S — HTTP body not closed (`PERF-103`)

```go
// bad
resp, err := http.Get(url)
if err != nil { return err }
// missing resp.Body.Close()

// good
resp, err := http.Get(url)
if err != nil { return err }
defer resp.Body.Close()
```

### A — unbounded package cache (`PERF-213`)

```go
// bad: package-level map grows forever
var cache = map[string]Result{}

// good: bounded LRU / TTL / size cap
```

### B — `time.Now().Sub` (`PERF-120`)

```go
// advisory
elapsed := time.Now().Sub(start)

// preferred
elapsed := time.Since(start)
```

### C — prefer staticcheck / prealloc

C-tier rules intentionally overlap ecosystem linters. Prefer those tools for CI
gates; keep C-tier under `--profile all` for inventory completeness.

---

## Framework coverage status

| Stack | Status |
|-------|--------|
| **net/http** | S-tier (timeouts, body close, client timeout) |
| **Gin** | S-tier body close + handler needles |
| **Echo** | Handler detection + sqlx/echo PERF rules |
| **Chi** | Request-path detection via `chi.URLParam` / router needles |
| **Fiber** | Handler detection via `*fiber.Ctx` |
| **GORM / sqlx** | N+1, scan, named query rules |
| **gRPC / redis** | Partial (e.g. KEYS); expand later |

---

## Hot-path policy

A site is hot when:

1. Inside a loop, or
2. Local window is handler-shaped (`ResponseWriter`, `*gin.Context`,
   `echo.Context`, `*fiber.Ctx`, `chi.URLParam`, …), or
3. Enclosing function name looks like `*Handler` / `*Middleware` / `ServeHTTP`

**Not** hot: bare `func (`, package-level init, `main`/`init`, broad names
(`build`, `process`, `generate`).

---

## How to inspect membership

```bash
codehound --explain PERF-103
codehound --list-rules --rule-category performance
```

---

## Real-world fixtures

Prefer multi-file / realistic packages under `tests/fixtures/go/perf_real_world/`
for S-tier rules (see `http_server-*`). Synthetic `package sample` twins remain
for unit inventory.

Human notes (partial catalog): [perf-rules.md](./perf-rules.md).
Propose new rules: [rule-rfc-template.md](./rule-rfc-template.md).

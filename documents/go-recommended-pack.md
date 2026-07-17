# Recommended pack

Default CLI profile: `--profile recommended` (also `CODEHOUND_PROFILE=recommended`).

## Goal

A small, high-signal CI gate: **PERF footguns** teams actually fix, plus **taint-core CWEs** when you enable taint (or use `--profile security`).

Bad practices (`BP-*`) are **off**. Fail policy defaults to **strict** (high+ only) unless you set `--warnings-as-errors` / `--no-fail`.

## Rules (exact list)

### PERF (S-tier)

| Rule | Why |
|------|-----|
| `PERF-1` | Regex compilation inside a loop |
| `PERF-7` | `defer` inside a loop in the same function scope; per-iteration function literals are excluded |
| `PERF-50` | `regexp.MatchString` inside a loop |
| `PERF-58` | Gin `c.Request.Body` not closed |
| `PERF-71` | GORM N+1 query pattern |
| `PERF-101` | `http.Server` missing timeouts |
| `PERF-103` | HTTP response body not closed |
| `PERF-189` | HTTP response body not drained before close |
| `PERF-190` | HTTP client missing timeout |

See also [`documents/perf-tiers.md`](./perf-tiers.md) for S/A/B/C policy.

### CWE (taint-core)

| Rule | Why |
|------|-----|
| `CWE-22` | Path traversal (taint) |
| `CWE-78` | OS command injection (taint) |
| `CWE-79` | XSS / template+HTTP write (taint) |
| `CWE-89` | SQL injection heuristic (taint) |
| `CWE-90` | LDAP injection (taint) |
| `CWE-91` | XML injection (taint) |

Taint analysis is **off** under `recommended` unless you pass `--taint`. The CWE IDs stay in the pack allow-list so `--taint --profile recommended` works without switching packs.

## Other profiles

| Profile | Contents | Taint | BP | Default fail |
|---------|----------|-------|----|--------------|
| `recommended` | table above | off | off | strict |
| `perf` | broader PERF pack | off | off | strict |
| `security` | structural + taint-core CWEs | **on** | off | strict |
| `style` | `BP-*` (BP-21/28 default-off) | off | on | no-fail |
| `all` | full catalog | off | on | medium-as-errors |

## Fixture-only quarantine

Rules tagged `fixture-only` (e.g. CWE-334/335/338/342/343 PRNG museum) are **never** in recommended/security. Use `--profile all` for the full corpus.

See `src/rules/maturity.rs` and `src/core/profile.rs`.

## CI one-liner

```bash
codehound --profile recommended --format sarif --strict . > codehound.sarif
```

Sample workflow: [`.github/workflows/codehound.yml`](../.github/workflows/codehound.yml).

## Brownfield

1. Start advisory: `--no-fail` or upload SARIF without blocking merge.
2. Save a baseline: `codehound --profile recommended --baseline .`
3. Suppress known noise: `// codehound-ignore: PERF-101` (or file-level ignore).

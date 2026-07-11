# CodeHound — Go PERF scanner + framework footgun detector

> A Rust static analyzer for Go. Finds **performance hot-path** regressions and
> **framework footguns** (Gin/Echo/GORM/sqlx) that lang linters miss. Curated
> CWE heuristics included. Runs offline, no toolchain required.

CodeHound is a fast, opinionated analyzer that **complements** golangci-lint,
staticcheck, and govulncheck — it targets what they don't see:

- **PERF** — 239 rules: regex-in-loops, `fmt.Sprintf` on hot paths, defer in tight loops, `http.ServeFile` body leaks, request-path allocation thrash. See [`docs/perf-rules.md`](./docs/perf-rules.md). Counts come from the live registry (`codehound --list-rules`).
- **Framework footguns** — Gin/Echo/GORM/sqlx aware: unclosed response bodies, unbounded query rows, missing timeouts, context leaks.
- **CWE heuristics** — 175 fixture-backed entries for file I/O, SQL injection, command injection, link resolution, and config sinks.
- **Bad practices** — 65 rules across error handling, concurrency, testing, API design, and prod hardening.
- **Taint tracking (experimental)** — intra-procedural for CWE-22/78/79/89. Name-string based; not security-grade — use for triage, not hard gating.

## Goals

- Detect statically visible performance and weakness patterns in Go services.
- Map findings to **PERF** rule IDs and **CWE** references.
- Emit machine-readable output (text, JSON, SARIF) — see [`docs/output-formats.md`](./docs/output-formats.md).
- Run as a single static binary, no external services.

## Who this is built for

Cloud AI subscriptions (ChatGPT, Claude, and the rest) are heavily
**subsidized** right now. That will not last forever — and even while it does,
open-ended agent loops still cost real money and real days.

CodeHound is aimed at **hobby projects** and **small-scale Go work**: places
where you do not need enterprise-grade performance engineering, but you still
want *some* optimization, cleaner architecture, and **less slop** in the
codebase — under a real delivery deadline. It was built for personal use under
those constraints: a deterministic, offline checklist you can run before (or
instead of) burning tokens on unbounded review.

**Run it after** your existing Go CI and linters — **golangci-lint**,
staticcheck, govulncheck, and the rest. CodeHound complements them with
hot-path PERF, framework footguns, and **bad-practice** rules those tools often
miss. It does not replace them. Language bar today is **Go-first**.

If you want less agent-shaped mess, better architecture habits, or a concrete
bad-practices catalog, use CodeHound **instead of open-ended skills** for that
pass: stable rule IDs, files, and lines — not a vibe that drifts every run.
Optional agent triage stays bounded; the checklist does not.

If you need full SRE / CodeQL-class coverage for a large org, use the tools
built for that. If you need a fast PERF + footgun + BP pass for a side project
or small Go service and want optional agent triage with a fixed budget, this is
for you.

## Status

**0.1.0** product bar. **Go-first:** production rules and packs target Go.
Python is an **opt-in** Cargo feature with a single experimental rule
(`SLOP101`). There is no TypeScript plugin. Complements golangci-lint;
see [`docs/go-vs-staticcheck.md`](./docs/go-vs-staticcheck.md) and
[`docs/adr/0005-multi-lang-honesty.md`](./docs/adr/0005-multi-lang-honesty.md).

## Roadmap

Live roadmap: **[`ROADMAP.md`](./ROADMAP.md)**. Historical plans under `plans/`
are archive notes, not the backlog.

## Installation

```sh
# Go-first default build
cargo install --path .

# Optional experimental Python (SLOP101 only)
cargo install --path . --features python
```

## Usage

```sh
# Default = recommended pack (S-tier PERF + taint-core CWEs; BP off; fail high)
codehound .

# Example PERF-style finding (request path / timeouts) — the product wedge
codehound --profile recommended --only PERF-101 .

# Security pack (enables taint) or full catalog
codehound --profile security .
codehound --profile all .

# JSON or SARIF output
codehound --format json ./...
codehound --format sarif ./... > out.sarif

# Test files (*_test.go, etc.) are excluded by default; include them with:
codehound --include-tests .

# Limit to specific rules (merged with pack allow-list)
codehound --only CWE-22,CWE-89 .

# Show every registered rule
codehound --list-rules

# Show details for a single rule
codehound --explain PERF-101

# Write a starter codehound.toml
codehound init

# Incremental analysis cache (enabled by default)
codehound --rebuild-cache .
codehound --prune-cache .
codehound --no-cache .
```

Profiles: [`docs/go-recommended-pack.md`](./docs/go-recommended-pack.md).  
Cache: [`docs/incremental-cache.md`](./docs/incremental-cache.md).  
Sample CI: [`.github/workflows/codehound.yml`](./.github/workflows/codehound.yml).

## Recommendation

**Use CodeHound after** golangci-lint + govulncheck for **app-level Go PERF + framework footguns + curated CWE heuristics** — not instead of them.

**Non-goals:** not a golangci-lint / staticcheck / govulncheck / CodeQL replacement; not a CVE scanner; not default-on full BP in CI.

Default pack is **`recommended`** (high signal, fail-on-high). Use `--profile all` only when you intentionally want the full catalog.

### Severity Levels

| Level    | Description                        | Exit (recommended pack) |
|----------|------------------------------------|-------------------------|
| Info     | Advisory                           | 0                       |
| Low      | Minor concern                      | 0                       |
| Medium   | Review (does not fail recommended) | 0                       |
| High     | Likely a real issue                | 1                       |
| Critical | Must fix immediately               | 1                       |

### SARIF output

Detailed SARIF schema reference, field mapping, and `security-severity` scoring
are documented in [`docs/output-formats.md`](./docs/output-formats.md#sarif-210).

Look for SARIF
compatibility notes in [`plans/v0.0.1/go/perf-heuristics-and-sarif.md`](./plans/v0.0.1/go/perf-heuristics-and-sarif.md)
(perf-rule-specific SARIF metadata is in progress).

### Diagnostics Summary

Pass `--diagnostics-summary` to print a compact scan summary to stderr:

```
scanned 238 files | 195 cached | 43 fresh | 1250.3ms | slowest: PERF-141
```

### Taint Tracking (experimental)

CodeHound includes an experimental intra-procedural taint-tracking engine for
CWE-22, CWE-78, CWE-79, and CWE-89. **Disabled by default** — pass `--taint` or
set `[codehound.taint] enabled = true`. **Not security-grade** — name-string sink
matching, no types; `filepath.Clean` alone is **not** treated as a path sanitizer.
Use for triage, not hard gating. See [`docs/taint.md`](./docs/taint.md).

### Canonical CI one-liner

Export is **off** by default (no writes under `scripts/`). Example:

```bash
# Default recommended pack → SARIF (fail high; no BP; no workspace dirt)
codehound --profile recommended --format sarif . > codehound.sarif

# Security pack (taint on)
codehound --profile security --format sarif . > codehound.sarif
```

### Bad Practices

65 Go bad-practice rules (`BP-*`) covering error handling,
concurrency, testing, API design, code organization, production hardening, and
dependency hygiene. Note: partial overlap with staticcheck/errcheck — CodeHound is best used as a complement, not a replacement. See [`docs/bad-practices.md`](./docs/bad-practices.md).

### Configuration file (`codehound.toml`)

All fields are optional. See `codehound init` for a starter template.

```toml
[codehound]
# Only analyze these languages.
# languages = ["go", "python"]

# Only run specific rules.
# only = ["CWE-22", "CWE-89"]

# Skip specific rules.
# skip = ["CWE-15"]

# Exit policy: "none" | "never" | "medium" | "warnings" | "high" | "strict".
# Unknown values are rejected at load time.
# fail_on = "high"

# Include/exclude gitignore-style globs.
# include = ["**/*.go"]
# exclude = ["**/vendor/**", "**/*_test.go"]

# Test files (*_test.*) are excluded by default; set to false to include them.
# exclude_tests = false
```

## Sample

A small Go file with path traversal:

```go
package sample

import (
    "net/http"
    "path/filepath"
)

func readFile(w http.ResponseWriter, r *http.Request) {
    requested := r.URL.Query().Get("path")
    full := filepath.Join("/srv/public", requested)
    http.ServeFile(w, r, full)
}
```

CodeHound output:

```
high  CWE-22  sample.go:10:13  user-controlled input reaches a filesystem path sink
```

## Development

```sh
cargo build
cargo test
cargo run -- ./tests/fixtures
```

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

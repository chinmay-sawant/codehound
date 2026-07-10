# CodeHound — Go PERF scanner + framework footgun detector

> A Rust static analyzer for Go. Finds **performance hot-path** regressions and
> **framework footguns** (Gin/Echo/GORM/sqlx) that lang linters miss. Curated
> CWE heuristics included. Runs offline, no toolchain required.

CodeHound is a fast, opinionated analyzer that **complements** golangci-lint,
staticcheck, and govulncheck — it targets what they don't see:

- **PERF** — 224 rules across 60+ detectors: regex-in-loops, `fmt.Sprintf` on hot paths, defer in tight loops, `http.ServeFile` body leaks, request-path allocation thrash. See [`docs/perf-rules.md`](./docs/perf-rules.md).
- **Framework footguns** — Gin/Echo/GORM/sqlx aware: unclosed response bodies, unbounded query rows, missing timeouts, context leaks.
- **CWE heuristics** — 175+ fixture-backed entries for file I/O, SQL injection, command injection, link resolution, and config sinks. Auto-generated from a central sink registry.
- **Bad practices** — 65 rules across error handling, concurrency, testing, API design, and prod hardening.
- **Taint tracking (experimental)** — intra-procedural for CWE-22/78/79/89. Name-string based; not security-grade — use for triage, not hard gating.

## Goals

- Detect statically visible performance and weakness patterns in Go services.
- Map findings to **PERF** rule IDs and **CWE** references.
- Emit machine-readable output (text, JSON, SARIF) — see [`docs/output-formats.md`](./docs/output-formats.md).
- Run as a single static binary, no external services.

## Status

Under active development. **Go is the production language** — Python (1 rule) and TypeScript (stub) are not yet meaningful. 

## Roadmap

| Phase | Theme | Status |
|------:|-------|--------|
| **p1** | Go CWE heuristic coverage | Implemented |
| **p2** | Broader language and rule coverage | In Progress |

## Installation

```sh
cargo install --path .
```

## Usage

```sh
# Analyze the current directory
codehound .

# Analyze a single file
codehound path/to/file.go

# JSON or SARIF output
codehound --format json ./...
codehound --format sarif ./... > out.sarif

# Test files (*_test.go, etc.) are excluded by default; include them with:
codehound --include-tests .

# Limit to specific rules
codehound --only CWE-22,CWE-89 .

# Show every registered rule
codehound --list-rules

# Show details for a single rule
codehound --explain CWE-89

# Write a starter codehound.toml
codehound init

# Incremental analysis cache (enabled by default)
#   .codehound-cache/ stores per-file findings keyed by content hash.
codehound .

# Force a fresh cache (purge then scan)
codehound --rebuild-cache .

# Prune stale cache entries without scanning
codehound --prune-cache .

# Disable the cache for this run
codehound --no-cache .
```

See [`docs/incremental-cache.md`](./docs/incremental-cache.md) for details on the cache format, invalidation strategy, and configuration.

## Recommendation

**Use CodeHound after** golangci-lint + govulncheck for **app-level Go PERF + framework footguns + curated CWE heuristics** — not instead of them. Scoped packs (PERF-only or high-severity CWE) give the best signal-to-noise ratio.

### Severity Levels

| Level    | Description                        | Exit Code |
|----------|------------------------------------|-----------|
| Info     | Advisory, no action needed         | 0         |
| Low      | Minor concern, review recommended  | 0         |
| Medium   | Should be fixed (default fail threshold) | 1    |
| High     | Likely a real issue                | 1         |
| Critical | Must fix immediately               | 1         |

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
# Advisory scan: SARIF for Code Scanning, no workspace dirt, fail on high only
codehound --format sarif --strict --no-bp . > codehound.sarif

# Security-oriented scan with taint core
codehound --taint --format sarif --strict . > codehound.sarif
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

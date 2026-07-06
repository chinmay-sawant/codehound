# CodeHound

> A static code analyzer written in Rust for detecting statically visible code
> weaknesses in supported codebases.

CodeHound is a fast, opinionated analyzer focused on **statically detectable
weaknesses** with the current Go implementation centered on bundled CWE
heuristics and fixture-backed regression coverage.

The CWE catalog has 175+ entries auto-generated from a central sink registry,
providing comprehensive coverage of known weakness patterns across file I/O,
SQL, command injection, link resolution, and configuration sinks.

A **PERF** (performance) rule catalog with 224 rules is also included; over 60
detectors are shipped covering common performance anti-patterns in Go. See
[`docs/perf-rules.md`](./docs/perf-rules.md) for the full catalog.

It is designed to **complement** existing language tooling with repository-local
heuristics, reusable fact extraction, and machine-readable findings.

## Goals

- Detect statically visible weakness patterns with reusable fact extraction.
- Map findings to **CWE** references for compliance workflows.
- Emit machine-readable output (text, JSON, SARIF) — see [`docs/output-formats.md`](./docs/output-formats.md).
- Run as a single static binary, no external services.

## Status

CodeHound is under active development. The current Go implementation centers on
fixture-backed CWE detection.

## Roadmap

See [`plans/`](./plans) for the detailed plan.

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

### Taint Tracking

CodeHound includes an experimental intra-procedural taint-tracking engine for
CWE-22, CWE-78, CWE-79, and CWE-89. See [`docs/taint.md`](./docs/taint.md)
for details.

### Bad Practices

65 Go bad-practice rules (`BP-*`) are shipped covering error handling,
concurrency, testing, API design, code organization, production hardening, and
dependency hygiene. See [`docs/bad-practices.md`](./docs/bad-practices.md).

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

# Exit policy: "none" | "high" | "strict" | anything else = warnings as errors.
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

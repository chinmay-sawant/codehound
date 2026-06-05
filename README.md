# SlopGuard

> A static code analyzer written in Rust for detecting statically visible code
> weaknesses in supported codebases.

SlopGuard is a fast, opinionated analyzer focused on **statically detectable
weaknesses** with the current Go implementation centered on bundled CWE
heuristics and fixture-backed regression coverage.

It is designed to **complement** existing language tooling with repository-local
heuristics, reusable fact extraction, and machine-readable findings.

## Goals

- Detect statically visible weakness patterns with reusable fact extraction.
- Map findings to **CWE** references for compliance workflows.
- Emit machine-readable output (text, JSON, SARIF).
- Run as a single static binary, no external services.

## Status

SlopGuard is under active development. The current Go implementation centers on
fixture-backed CWE detection.

## Roadmap

See [`plans/`](./plans) for the detailed plan.

| Phase | Theme | Status |
|------:|-------|--------|
| **p1** | Go CWE heuristic coverage | Implemented |
| **p2** | Broader language and rule coverage | Planned |
| **p3** | CVE (Common Vulnerabilities and Exposures) coverage | Planned |

## Installation

```sh
cargo install --path .
```

## Usage

```sh
# Analyze the current directory
slopguard .

# Analyze a single file
slopguard path/to/file.go

# JSON or SARIF output
slopguard --format json ./...
slopguard --format sarif ./... > out.sarif

# Limit to specific rules
slopguard --only CWE-22,CWE-89 .

# Show every registered rule
slopguard --list-rules

# Show details for a single rule
slopguard --explain CWE-89

# Write a starter slopguard.toml
slopguard init
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

SlopGuard output:

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

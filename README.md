# SlopGuard

> A static code analyzer written in Rust for detecting performance bottlenecks
> and "slop" in Go codebases.

SlopGuard is a fast, opinionated linter focused on **statically detectable
performance issues** that frequently appear in real Go code: regex
compilation inside hot loops, repeated allocations, slice/map rebuilds,
string concatenation in tight paths, and other "the code works, but it's
slow" anti-patterns.

It is designed to **complement** [Staticcheck](https://staticcheck.dev) by
going deeper on **loop + data-flow awareness** — the patterns that classic
AST-only linters miss.

## Goals

- Detect performance smells with **loop + data-flow** context.
- Map findings to **CWE** references for compliance workflows
  (CWE-400, CWE-407, CWE-770, CWE-1336, ...).
- Emit machine-readable output (text, JSON, **SARIF** — planned).
- Run as a single static binary, no external services.

## Status

SlopGuard is in **early bootstrap**. The current build only implements
`regexp_in_loop`. The roadmap below shows what's coming next.

## Roadmap

See [`plans/`](./plans) for the detailed plan.

| Phase | Theme | Status |
|------:|-------|--------|
| **p1** | Static analysis — performance & slop (this codebase's main focus) | Bootstrapping |
| **p2** | CWE (Common Weakness Enumeration) coverage | Planned |
| **p3** | CVE (Common Vulnerabilities and Exposures) coverage | Planned |

### Near-term detectors

- `regexp_in_loop` — `regexp.MustCompile` / `regexp.Compile` inside `for` body
- `string_concat_in_loop` — `s = s + ...` or `s += ...` inside `for`
- `slice_rebuild_in_loop` — `slice = append(slice, ...)` then re-declared
- `map_alloc_in_loop` — `make(map[..]..)` inside `for`
- `json_marshal_in_loop` — `json.Marshal/Unmarshal` inside hot path

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

# JSON output (SARIF coming soon)
slopguard --format json ./...
```

## Sample

A small Go file with classic slop:

```go
package sample

import "regexp"

func bad(rows []string) []string {
    var out []string
    for _, r := range rows {
        re := regexp.MustCompile(`^\d+`) // ← compiled every iteration
        if re.MatchString(r) {
            out = append(out, r)
        }
    }
    return out
}
```

SlopGuard output:

```
warning  regexp_in_loop  sample.go:7:5  regexp.MustCompile called inside loop body
                                    ↳ CWE-400 (Uncontrolled Resource Consumption)
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

# CLI reference

Canonical flag and subcommand surface for the `codehound` binary. Short recipes
live in the root [README](../README.md); config details in
[configuration.md](./configuration.md); formats and exit codes in
[output-formats.md](./output-formats.md).

```text
codehound [OPTIONS] [PATH]... [COMMAND]
```

Bare paths mean **scan** (default path: `.`). Global flags apply to scans and
to most subcommands that re-run analysis (for example `baseline save`).

---

## Subcommands

| Command | Purpose |
|---------|---------|
| `codehound [PATH…]` | Scan (default action) |
| `codehound scan [PATH…]` | Explicit scan; same defaults as bare invocation |
| `codehound init` | Write a starter `codehound.toml` if none exists (exit `2` if present) |
| `codehound rules` | List rules or explain one (`--category`, `--explain RULE`) |
| `codehound cache prune` | Drop stale / orphaned incremental-cache entries, then exit |
| `codehound baseline list` | List baselined fingerprints (`--path` for file) |
| `codehound baseline save` | Scan and write findings as baseline |
| `codehound baseline update` | Merge current findings into the baseline |
| `codehound baseline prune` | Drop baseline entries that no longer match live findings |
| `codehound baseline diff` | Diff live findings vs baseline |
| `codehound help` | Clap help |

Top-level convenience flags (no subcommand): `--list-rules`, `--explain RULE`,
`--prune-cache`, `--baseline` (save baseline and exit).

---

## Profiles

| Value | Aliases | Rules | Taint | BP | Default fail |
|-------|---------|-------|-------|----|--------------|
| `recommended` (default) | `ci`, `default` | S-tier PERF + taint-core CWEs | off | off | **strict** (high+) |
| `perf` | — | S+A PERF | off | off | strict |
| `security` | `sec` | Security pack CWEs | **on** | off | strict |
| `style` | `bp`, `bad-practices` | `BP-*` (skips BP-21/28/30) | off | on | **no-fail** |
| `all` | `full` | Full catalog | off | on | medium-as-errors |

Env: `CODEHOUND_PROFILE`.

Exact pack membership: [go-recommended-pack.md](./go-recommended-pack.md),
[perf-tiers.md](./perf-tiers.md).

### What fails under recommended

- Fail policy **strict** = process exit `1` only for **high** / **critical**.
- S-tier PERF rules are **medium** severity → visible, **non-failing** under
  recommended unless you pass `--warnings-as-errors`.
- Taint-core CWEs are high when they fire; taint itself is **off** until
  `--taint` or `--profile security`.

---

## Global flags

### Output

| Flag | Purpose |
|------|---------|
| `--format text\|json\|sarif` | Reporter (default `text`) |
| `--json-envelope` | JSON as one object (requires `--format json`) |
| `--sarif-compact` | Single-line SARIF (requires `--format sarif`) |
| `--no-snippet` | Hide source snippets in text |
| `--quiet` | Suppress non-error output |
| `--no-terminal` | Do not print findings to stdout |
| `--no-color` | Disable color (`NO_COLOR` also honored) |
| `--verbose` | Extra detector detail in text |
| `--show-fingerprint` | Print fingerprints in text |

### Profiles & rules

| Flag | Purpose |
|------|---------|
| `--profile …` | Product pack (see above) |
| `--only IDS` | Only these rule IDs (comma-separated; env `CODEHOUND_ONLY`) |
| `--skip IDS` | Skip these IDs (env `CODEHOUND_SKIP`) |
| `--bp-only` / `--no-bp` | Only bad-practice rules, or disable them |
| `--list-rules` | List registered rules and exit |
| `--rule-category security\|performance\|bad-practice\|general` | Filter `--list-rules` |
| `--explain RULE` | Deep-dive one rule (pack, maturity, quarantine) |
| `--config PATH` | Override `codehound.toml` discovery (env `CODEHOUND_CONFIG`) |

`only` / `skip` accept exact IDs and simple globs such as `BP-*`.

### Taint & typed Go

| Flag | Purpose |
|------|---------|
| `--taint` / `--no-taint` | Toggle experimental taint engine |
| `--taint-show-paths` | Emit taint-path evidence |
| `--taint-depth N` | Inter-procedural hops (1–4, default 1) |
| `--typed` / `--no-typed` | Optional `go list` package facts (G4); needs a Go toolchain |

`CODEHOUND_GO` may point at a specific `go` binary when `--typed` is on.

### Exit policy

| Flag | Effect |
|------|--------|
| (profile default) | See profile table |
| `--strict` | Fail only on high+ (CLI-explicit; wins over config `fail_on`) |
| `--warnings-as-errors` | Fail on medium+ (CLI-explicit) |
| `--no-fail` | Always exit 0 for findings |

There is **no** CLI flag `--fail-on`. Config uses `fail_on`; CLI uses the three
flags above. See [configuration.md](./configuration.md).

### Cache, baseline, discovery

| Flag | Purpose |
|------|---------|
| `--no-cache` | Disable incremental cache for this run |
| `--rebuild-cache` | Wipe cache and rescan |
| `--prune-cache` | Housekeeping prune, then exit |
| `--cache-dir DIR` | Override cache directory |
| `--baseline` | Save baseline from this scan and exit |
| `--no-baseline` | Ignore baseline file |
| `--baseline-file PATH` | Custom baseline path |
| `--show-baselined` | Emit baselined findings |
| `--show-ignored` | Emit `codehound-ignore` suppressions |
| `--include-tests` | Include `*_test.*` (excluded by default) |
| `--exclude-examples` | Skip examples / samples paths |
| `--lang auto\|go\|python` | Language filter (Python needs `--features python`) |

### Agent export (opt-in)

| Flag | Purpose |
|------|---------|
| `--export-context` | One file per finding (default dir: `scripts/findings/functions`) |
| `--export-chunks` | Batched chunk files (default dir: `scripts/chunks`) |
| `--chunk-size N` | Findings per chunk (default 25) |
| `--context-output-dir` / `--chunks-output-dir` | Override export dirs |

### Diagnostics

| Flag | Purpose |
|------|---------|
| `--diagnostics-summary` | Compact stderr summary (files, cache, time) |
| `--diagnostics FILE` | Machine-readable diagnostics JSON |
| `--debug-timing` | Per-detector timing after findings |

---

## Environment variables

| Variable | Equivalent |
|----------|------------|
| `CODEHOUND_PROFILE` | `--profile` |
| `CODEHOUND_CONFIG` | `--config` |
| `CODEHOUND_ONLY` | `--only` |
| `CODEHOUND_SKIP` | `--skip` |
| `NO_COLOR` | `--no-color` (truthy values) |
| `CODEHOUND_GO` | Path to `go` for `--typed` |
| `RUST_LOG` | Tracing verbosity (`debug`/`info`/…); not a product flag |

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no failing findings, no scan errors |
| `1` | Findings exceeded the fail policy |
| `2` | Configuration / CLI error |
| `3` | Internal, I/O, encoding, or aborted engine error |
| `4` | Per-file parse error (tree-sitter) |
| `5` | Per-file detector/engine error |
| `101` | Rust panic in a worker thread |

Scan errors take precedence over finding fail policy. Full reporter details:
[output-formats.md](./output-formats.md).

---

## Recipes

```sh
# Default CI pack
codehound .

# Gate on medium PERF as well
codehound --warnings-as-errors .

# Security pack (taint on)
codehound --profile security .

# SARIF for GitHub Code Scanning
codehound --format sarif . > codehound.sarif

# Brownfield baseline
codehound --no-fail .
codehound --baseline .
codehound baseline diff .

# Agent export (local remediation; keep off pure CI gates)
codehound --profile all --export-context --export-chunks --no-cache .

# Rule browser
codehound --list-rules --rule-category performance
codehound --explain PERF-103
codehound rules --explain CWE-89

# Typed package facts (optional)
codehound --typed .
```

CI workflow and composite action: [ci-integration.md](./ci-integration.md).

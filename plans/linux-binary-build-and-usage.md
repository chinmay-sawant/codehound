# CodeHound Linux Binary — Build, Setup & Usage Guide

> **Status:** Built and verified on Linux (WSL2) — 2026-07-08  
> **Binary version:** `codehound 0.0.1`  
> **Binary size:** ~6.6 MB (release, stripped symbols)

This document covers how the Linux binary was built, how to install it on any machine, how to run it from any directory (current path `.` or a custom path), and every CLI parameter CodeHound supports.

---

## Table of Contents

1. [What CodeHound Does](#what-codehound-does)
2. [Build the Linux Binary](#build-the-linux-binary)
3. [Binary Location](#binary-location)
4. [Setup & Installation](#setup--installation)
5. [Running from Any Directory](#running-from-any-directory)
6. [Scanning the Current Directory (`.`)](#scanning-the-current-directory-)
7. [Scanning a Custom Path](#scanning-a-custom-path)
8. [Configuration (`codehound.toml`)](#configuration-codehoundtoml)
9. [Environment Variables](#environment-variables)
10. [Complete CLI Reference](#complete-cli-reference)
11. [Common Workflows](#common-workflows)
12. [Troubleshooting](#troubleshooting)

---

## What CodeHound Does

CodeHound is a **single static binary** static analyzer written in Rust. It requires **no API keys, no network, and no external services**.

| Capability | Details |
|------------|---------|
| **Languages** | Go (175+ CWE, 230+ PERF, 65 BP-* rules), Python (`SLOP101`) |
| **Output formats** | `text` (default), `json` (NDJSON or envelope), `sarif` 2.1.0 |
| **Features** | Incremental cache, baseline suppression, taint tracking (experimental), bad-practice rules |
| **MSRV** | Rust 1.85+ (only needed to *build*; the binary runs standalone) |

---

## Build the Linux Binary

### Prerequisites

```sh
# Rust 1.85 or newer
rustup toolchain install stable
rustc --version   # must be >= 1.85
```

### Production build (recommended)

From the repository root:

```sh
cd /home/chinmay/ChinmayPersonalProjects/codehound
cargo build --release
```

**Output:** `target/release/codehound`

The release profile uses `opt-level = 3`, thin LTO, `codegen-units = 1`, and strips symbols — producing a ~6.6 MB optimized binary.

### Debug build (faster compile, larger binary)

```sh
cargo build
# → target/debug/codehound  (~88 MB, unoptimized)
```

### Feature-specific builds

```sh
# Go only (no Python)
cargo build --release --no-default-features --features go,cli

# Python only
cargo build --release --no-default-features --features python,cli
```

### Verify the build

```sh
./target/release/codehound --version    # codehound 0.0.1
./target/release/codehound --help
./target/release/codehound --list-rules
```

---

## Binary Location

| Build profile | Absolute path |
|---------------|---------------|
| **Release (production)** | `/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound` |
| Debug | `/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound` |
| After `cargo install --path . --release` | `~/.cargo/bin/codehound` |

> `target/` is gitignored. Rebuild with `cargo build --release` after pulling changes.

---

## Setup & Installation

Choose one of the following methods to make `codehound` available system-wide.

### Option A — Add to PATH (recommended for a local build)

Copy or symlink the release binary into a directory already on your `PATH`:

```sh
# Symlink (keeps binary in sync with rebuilds)
ln -sf /home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
       ~/.local/bin/codehound

# Or copy (independent of rebuilds)
mkdir -p ~/.local/bin
cp /home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
   ~/.local/bin/codehound
chmod +x ~/.local/bin/codehound
```

Ensure `~/.local/bin` is on your PATH (add to `~/.bashrc` or `~/.zshrc` if needed):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Verify:

```sh
codehound --version
```

### Option B — `cargo install` (rebuilds from source)

```sh
cd /home/chinmay/ChinmayPersonalProjects/codehound
cargo install --path . --release
# Installs to ~/.cargo/bin/codehound
```

Ensure `~/.cargo/bin` is on your PATH (rustup usually adds this automatically).

### Option C — Run by absolute path (no setup)

Use the full path every time — no installation needed:

```sh
/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound .
```

### Option D — Project-local binary

Copy into your project for a pinned version:

```sh
cp /home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
   /path/to/your/project/bin/codehound
./bin/codehound .
```

### First-time project setup

In the directory you want to analyze:

```sh
cd /path/to/your/go-project
codehound init          # writes a starter codehound.toml (fails if one exists)
codehound .             # first scan
```

No other setup is required. Cache (`.codehound-cache/`) and baseline files are created automatically on first run.

---

## Running from Any Directory

CodeHound is invoked from **your shell's current working directory** (`cwd`). The binary itself can live anywhere; what matters is **where you `cd` before running it** and **what path argument you pass**.

### Key rule: config discovery uses `cwd`, not the scan path

`codehound.toml` and `.codehound-baseline.json` are discovered by walking **upward from your current working directory**, not from the scan path argument.

| You are in | You run | Config discovered from | Code scanned |
|------------|---------|------------------------|--------------|
| `/home/me/myapp` | `codehound .` | `/home/me/myapp` upward | `/home/me/myapp` |
| `/tmp` | `codehound /home/me/myapp` | `/tmp` upward (may miss myapp's config!) | `/home/me/myapp` |
| `/home/me/myapp` | `codehound /other/repo` | `/home/me/myapp` upward | `/other/repo` |

**To analyze another repo with its own config:** either `cd` into that repo, or pass `--config /path/to/codehound.toml`.

### Example: run from `/tmp` against another project

```sh
cd /tmp

# Scan a remote path (no config from that repo unless you pass --config)
/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
  --no-fail /home/chinmay/ChinmayPersonalProjects/codehound/tests/fixtures

# Scan with explicit config from the target project
/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
  --config /home/chinmay/ChinmayPersonalProjects/codehound/codehound.toml \
  /home/chinmay/ChinmayPersonalProjects/codehound/tests/fixtures
```

### Example: run from your project root (recommended)

```sh
cd /home/me/my-go-service
codehound .                              # uses ./codehound.toml if present
codehound --format sarif . > report.sarif
```

---

## Scanning the Current Directory (`.`)

The `PATH` positional argument defaults to `.` when omitted. These are all equivalent when run from `/home/me/myapp`:

```sh
cd /home/me/myapp

codehound                    # implicit .
codehound .                  # explicit current directory
codehound ./                 # same as .
codehound --format json .    # JSON output for cwd
codehound --only CWE-22 .    # filter rules, scan cwd
```

### Typical first scan

```sh
cd /home/me/my-go-service
codehound init               # optional: create codehound.toml
codehound .                  # scan everything in cwd (respects .gitignore)
```

### CI-style scan of cwd

```sh
cd "$GITHUB_WORKSPACE"
codehound --format sarif --no-fail . > codehound.sarif
```

### Quiet scan (errors only)

```sh
cd /home/me/myapp
codehound --quiet --no-fail .
```

### Scan cwd with diagnostics

```sh
cd /home/me/myapp
codehound --diagnostics-summary --diagnostics /tmp/scan-diag.json .
```

---

## Scanning a Custom Path

Pass one or more paths after the flags. Paths can be **files**, **directories**, or **multiple roots**.

### Single file

```sh
codehound ./cmd/server/main.go
codehound /absolute/path/to/handler.go
```

### Directory (recursive)

```sh
codehound /home/me/my-go-service
codehound src/ internal/
```

### Multiple paths

```sh
codehound src/ pkg/ cmd/
codehound ./handler.go ./middleware.go
```

### Fixture files (`.txt` auto-materialized)

```sh
codehound tests/fixtures/go/perf/PERF-213-vulnerable.txt
# Materialized to target/codehound-fixtures/ before scanning
```

### From a different cwd than the scan target

```sh
# You are NOT in the project — pass absolute path + explicit config
cd ~
codehound --config /home/me/other-project/codehound.toml \
          /home/me/other-project
```

### Makefile-style custom path

The repo's `makefile` uses a `SCAN_PATH` variable (defaulting to an external project):

```sh
cd /home/chinmay/ChinmayPersonalProjects/codehound
make run SCAN_PATH=.                           # scan this repo
make run SCAN_PATH=tests/fixtures RUN_ARGS="--format json"
```

---

## Configuration (`codehound.toml`)

### Discovery

Walks upward from **cwd**:

```
./codehound.toml → ../codehound.toml → ... → filesystem root
```

Override: `--config <PATH>` or `CODEHOUND_CONFIG=<PATH>`.

### Create a starter config

```sh
codehound init    # writes templates/codehound.toml → ./codehound.toml
```

### Key sections

```toml
[codehound]
# languages = ["go", "python"]
# only = ["CWE-22", "CWE-89"]
# skip = ["CWE-15"]
# fail_on = "high"          # "none" | "high" | "strict" | default = medium-as-errors
# include = ["**/*.go"]
# exclude = ["**/vendor/**"]
# exclude_tests = false     # test files excluded by default

[codehound.baseline]
# enabled = true
# path = ".codehound-baseline.json"

[codehound.cache]
# enabled = true
# path = ".codehound-cache"
# max_size_mb = 500

[codehound.bad_practices]
# enabled = true
# severity = "medium"

[codehound.taint]
# enabled = true
# show_paths = true
```

### Precedence (highest → lowest)

1. CLI flags
2. `codehound.toml`
3. Built-in defaults

`--only` and `--skip` are **merged** (additive) with config values.

### Ignore files

- `.codehoundignore` — project-specific globs
- `.gitignore` and `.ignore` — respected automatically

Full schema: `codehound.schema.json`  
Full docs: `documents/configuration.md`

---

## Environment Variables

| Variable | Equivalent flag | Description |
|----------|-----------------|-------------|
| `CODEHOUND_CONFIG` | `--config` | Path to `codehound.toml` |
| `CODEHOUND_ONLY` | `--only` | Comma-separated rule IDs to run |
| `CODEHOUND_SKIP` | `--skip` | Comma-separated rule IDs to skip |
| `NO_COLOR` | `--no-color` | Disable colored output (`1`, `true`, etc.) |
| `RUST_LOG` | — | Tracing verbosity (`warn`, `codehound=info`, `debug`) |

Examples:

```sh
export CODEHOUND_ONLY=CWE-22,CWE-89
codehound .

CODEHOUND_CONFIG=/path/to/codehound.toml codehound .

NO_COLOR=1 codehound .

RUST_LOG=codehound=info codehound --diagnostics-summary .
```

---

## Complete CLI Reference

### Positional arguments

| Argument | Form | Default | Description |
|----------|------|---------|-------------|
| `PATH` | `[PATH]...` | `.` | Files or directories to analyze. Repeatable. |

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `init` | Write starter `codehound.toml` to cwd (errors if file exists) |
| `help` | Print help (`codehound help`, `codehound help init`) |

### Built-in flags

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Print help |
| `-V`, `--version` | Print version (`codehound 0.0.1`) |

---

### Language & output

| Flag | Env | Default | Values | Description |
|------|-----|---------|--------|-------------|
| `--lang` | — | `auto` | `auto`, `go`, `python` | Language filter |
| `--format` | — | `text` | `text`, `json`, `sarif` | Output format |
| `--config` | `CODEHOUND_CONFIG` | auto-discover | path | Config file path |

```sh
codehound --lang go .
codehound --format json . > findings.json
codehound --format sarif . > report.sarif
codehound --format json --json-envelope . > envelope.json
```

---

### Rule filtering

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--only` | `CODEHOUND_ONLY` | `[]` | Only run these rule IDs (comma-separated) |
| `--skip` | `CODEHOUND_SKIP` | `[]` | Skip these rule IDs |
| `--bp-only` | — | `false` | Only bad-practice rules (`BP-*`) |
| `--no-bp` | — | `false` | Disable all `BP-*` rules |
| `--list-rules` | — | `false` | List all rules and exit |
| `--rule-category` | — | — | Filter `--list-rules`: `security`, `performance`, `bad-practice`, `general` |
| `--explain` | — | — | Show details for one rule ID and exit |

```sh
codehound --only CWE-22,CWE-89 .
codehound --skip PERF-001 .
codehound --bp-only .
codehound --no-bp --only CWE-89 .
codehound --list-rules
codehound --list-rules --rule-category security
codehound --explain CWE-89
```

---

### Taint tracking (experimental)

| Flag | Default | Description |
|------|---------|-------------|
| `--taint` | `false` | Enable taint engine for CWE-22/78/79/89 |
| `--no-taint` | `false` | Disable taint even if config enables it |
| `--taint-show-paths` | `false` | Include taint-path evidence in output |

```sh
codehound --taint .
codehound --taint --taint-show-paths --format json .
```

---

### Exit policy (mutually exclusive — only one at a time)

| Flag | `FailPolicy` | Behavior |
|------|--------------|----------|
| *(default)* | `MediumAsErrors` | Exit non-zero on medium, high, critical findings |
| `--warnings-as-errors` | `MediumAsErrors` | Same as default; marks explicit CLI choice |
| `--strict` | `Strict` | Exit non-zero only on high/critical |
| `--no-fail` | `NoFail` | Always exit 0 regardless of findings |

```sh
codehound --strict .          # CI: fail only on serious issues
codehound --no-fail .         # report findings but never fail the job
```

---

### Output control

| Flag | Default | Description |
|------|---------|-------------|
| `--quiet` | `false` | Suppress all output except errors (global) |
| `--no-color` | `false` | Disable colored output |
| `--no-terminal` | `false` | Don't print findings to stdout |
| `--no-context` | `false` | Don't write per-finding context files |
| `--no-chunks` | `false` | Don't write chunk files |
| `--no-snippet` | `false` | Suppress source snippets in output |
| `--show-fingerprint` | `false` | Show finding fingerprints in text output |
| `--verbose` | `false` | Extra detector details in text output |
| `--json-envelope` | `false` | Single JSON object instead of NDJSON lines |

```sh
codehound --no-color --verbose .
codehound --no-terminal --no-context --no-chunks .
codehound --format json --json-envelope . > report.json
```

---

### Diagnostics & timing

| Flag | Default | Description |
|------|---------|-------------|
| `--debug-timing` | `false` | Print per-detector timing after findings |
| `--diagnostics` | — | Write scan diagnostics JSON to `FILE` |
| `--diagnostics-summary` | `false` | Compact summary to stderr (files, cache, timing) |

```sh
codehound --diagnostics-summary .
codehound --diagnostics /tmp/diag.json .
codehound --debug-timing --diagnostics-summary .
```

---

### Export paths

| Flag | Default | Description |
|------|---------|-------------|
| `--chunk-size` | `25` | Findings per chunk file |
| `--context-output-dir` | `scripts/findings/functions` | Per-finding context files |
| `--chunks-output-dir` | `scripts/chunks` | Chunk output directory |

```sh
codehound --chunk-size 50 .
codehound --context-output-dir /tmp/context --chunks-output-dir /tmp/chunks .
```

---

### Baseline

| Flag | Default | Description |
|------|---------|-------------|
| `--baseline` | `false` | Save current findings as baseline and exit |
| `--no-baseline` | `false` | Ignore existing baseline file |
| `--baseline-file` | — | Custom baseline file path |
| `--show-ignored` | `false` | Report findings suppressed by `codehound-ignore` comments |

```sh
codehound --baseline .                              # creates .codehound-baseline.json
codehound .                                         # subsequent runs suppress baseline findings
codehound --no-baseline .                           # ignore baseline
codehound --baseline-file ./ci-baseline.json .
codehound --show-ignored .
```

---

### Cache

| Flag | Default | Description |
|------|---------|-------------|
| `--include-tests` | `false` | Include `*_test.*` files |
| `--no-cache` | `false` | Disable incremental cache for this run |
| `--cache-dir` | `.codehound-cache/` | Custom cache directory |
| `--rebuild-cache` | `false` | Purge cache then scan |
| `--prune-cache` | `false` | Remove stale entries and exit (no scan) |

```sh
codehound .                          # uses cache (default)
codehound --no-cache .
codehound --rebuild-cache .
codehound --prune-cache .
codehound --cache-dir /tmp/ch-cache .
codehound --include-tests .
```

---

## Common Workflows

### Daily development

```sh
cd ~/projects/my-service
codehound .                                    # quick scan
codehound --only CWE-89,CWE-78 .              # security-focused
codehound --bp-only --no-fail .               # bad practices only, non-blocking
```

### CI pipeline (GitHub Actions style)

```sh
cd "$REPO_ROOT"
codehound --format sarif --no-fail . > codehound.sarif
# Upload codehound.sarif to your SARIF viewer
```

### Strict CI gate

```sh
cd "$REPO_ROOT"
codehound --strict --format json . > findings.json
# Exit code non-zero if high/critical findings exist
```

### Establish and use a baseline

```sh
cd ~/projects/my-service
codehound --baseline .                         # snapshot current findings
# Fix some issues, then:
codehound .                                    # only new findings reported
```

### Performance audit

```sh
cd ~/projects/my-service
codehound --list-rules --rule-category performance
codehound --only PERF-213,PERF-224 --format json .
```

### Security audit with taint

```sh
cd ~/projects/my-service
codehound --taint --taint-show-paths --only CWE-22,CWE-89,CWE-78 .
```

### Scan a dependency or monorepo sub-package

```sh
cd ~/projects/monorepo
codehound ./services/api/
codehound ./services/api ./services/worker
```

### Analyze a repo you are not inside

```sh
# Best: cd into the repo
cd /path/to/external-repo && codehound .

# Alternative: stay in cwd, pass path + config
codehound --config /path/to/external-repo/codehound.toml \
          /path/to/external-repo
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `codehound: command not found` | Add `~/.local/bin` or `~/.cargo/bin` to PATH, or use absolute path |
| Config not picked up when scanning remote path | `cd` into the target repo, or use `--config` |
| Too many findings in CI | Use `--baseline` to suppress known issues, or `--only` to narrow rules |
| Slow first run | Normal — cache warms on subsequent runs (`.codehound-cache/`) |
| Test files not scanned | Add `--include-tests` (excluded by default) |
| Colors in piped output | Use `--no-color` or `NO_COLOR=1` |
| Need rule details | `codehound --explain CWE-89` or `codehound --list-rules` |

### Rebuild after code changes

```sh
cd /home/chinmay/ChinmayPersonalProjects/codehound
cargo build --release
# Binary updated at target/release/codehound
```

---

## Quick Reference Card

```sh
# BUILD
cargo build --release
# → target/release/codehound

# INSTALL (pick one)
ln -sf $(pwd)/target/release/codehound ~/.local/bin/codehound
cargo install --path . --release

# RUN — current directory
cd /path/to/project && codehound .

# RUN — custom path from anywhere
codehound /path/to/project
codehound /path/to/file.go

# RUN — absolute binary, any directory
/home/chinmay/ChinmayPersonalProjects/codehound/target/release/codehound \
  --no-fail /path/to/scan

# SETUP new project
cd /path/to/project && codehound init && codehound .

# HELP
codehound --help
codehound --list-rules
codehound --explain CWE-89
```

---

## Source References

| Topic | File |
|-------|------|
| CLI argument definitions | `src/cli/args.rs` |
| Subcommands & enums | `src/cli/enums.rs` |
| Severity / exit policy | `src/cli/severity_args.rs` |
| Command routing | `src/app/run.rs` |
| Config discovery | `src/app/config.rs` |
| Build config | `Cargo.toml` |
| Config template | `templates/codehound.toml` |
| User docs | `README.md`, `documents/configuration.md`, `documents/output-formats.md` |
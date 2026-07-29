# Configuration (`codehound.toml`)

CodeHound reads an optional `codehound.toml` from the current directory or any
parent directory. All fields are optional; the file may be empty.

Unknown fields are **rejected** with a parse error — there is no silent
fallback for typos. Generate a commented starter with `codehound init`.

JSON Schema: [`codehound.schema.json`](../codehound.schema.json) (repo root).  
CLI surface: [cli.md](./cli.md).  
Pack defaults: [go-recommended-pack.md](./go-recommended-pack.md).

---

## Discovery

Lookup walks from the current directory upward:

```text
./codehound.toml
../codehound.toml
… up toward the filesystem root
```

Override with `--config <PATH>` or `CODEHOUND_CONFIG=<PATH>`.

---

## Schema reference

```toml
[codehound]
# Restrict analysis. Values: "go", "python" (alias "py").
# languages = ["go"]

# Rule filters (merged with CLI --only / --skip; globs like "BP-*" allowed).
# only = ["CWE-22", "PERF-101"]
# skip = ["CWE-15"]

# Exit policy when CLI does not set --strict / --no-fail / --warnings-as-errors.
# "none" | "never" | "medium" | "warnings" | "high" | "strict"
# recommended / security / perf profiles default to high when unset on the CLI.
# fail_on = "high"

# Path globs relative to each scan root.
# include = ["**/*.go"]
# exclude = ["**/vendor/**"]

# Test files (*_test.*) excluded by default. Set false or pass --include-tests.
# exclude_tests = true

# [codehound.baseline]
# enabled = true
# path = ".codehound-baseline.json"

# [codehound.cache]
# enabled = true
# path = ".codehound-cache"
# max_size_mb = 500
# evict_target_ratio = 0.9
# max_file_size_mb = 4

# [codehound.taint]
# enabled = false
# show_paths = false

# [codehound.bad_practices]
# enabled = true
# severity = "medium"                    # optional override for all BP-*
# severity_overrides = { "BP-1" = "high" }
```

### Tables

| Table / key | Purpose |
|-------------|---------|
| `languages` | Limit plugins (`go`, `python`/`py`) |
| `only` / `skip` | Rule allow / deny lists (exact or simple `*` globs) |
| `fail_on` | Config-side exit policy (see below) |
| `include` / `exclude` | gitignore-style path globs |
| `exclude_tests` | Default `true`; CLI `--include-tests` opts in |
| `baseline` | Enable + path for `.codehound-baseline.json` |
| `cache` | Incremental analysis cache (see [incremental-cache.md](./incremental-cache.md)) |
| `taint` | Experimental taint engine (see [taint.md](./taint.md)) |
| `bad_practices` | BP enable + severity overrides |

**Typed Go package facts** (`--typed` / `--no-typed`) are primarily CLI-driven
today. Optional toolchain path: `CODEHOUND_GO`. There is no required
`[codehound.typed]` block in the published JSON Schema; prefer CLI flags unless
your template documents an experimental key.

Product packs (`--profile`) are **not** a `codehound.toml` field — set them on
the CLI or via `CODEHOUND_PROFILE`.

---

## Fail policy

### Config strings (`fail_on`)

| Value | Behavior |
|-------|----------|
| `none`, `never` | Never fail for findings |
| `medium`, `warnings` | Fail on medium and above |
| `high`, `strict` | Fail on high and critical only |

### CLI flags (always win when set)

| Flag | Behavior |
|------|----------|
| `--no-fail` | Never fail for findings |
| `--warnings-as-errors` | Fail on medium+ |
| `--strict` | Fail on high+ only |

There is **no** CLI flag named `--fail-on`.

### Profile defaults (when CLI does not set a severity flag)

| Profile | Default fail |
|---------|--------------|
| `recommended`, `perf`, `security` | strict (high+) |
| `style` | no-fail |
| `all` | medium-as-errors |

Library / embedder defaults without a profile may still use medium-as-errors;
CLI users hit the **profile** defaults above.

### PERF under recommended

S-tier PERF rules are **medium** severity. With the recommended profile’s
default **strict** fail policy they **do not** fail CI. Use
`--warnings-as-errors` if you want medium PERF to gate merges.

---

## Precedence (highest to lowest)

1. **CLI-explicit** severity flags (`--strict`, `--no-fail`, `--warnings-as-errors`)
2. Other **CLI flags** (`--only`, `--skip`, `--taint`, `--no-taint`, `--typed`,
   `--no-cache`, `--baseline` / `--no-baseline` / `--baseline-file`, …)
3. **Profile** allow-lists and default fail policy (`--profile` / `CODEHOUND_PROFILE`)
4. **`codehound.toml`**
5. Built-in detector / engine defaults

Notes:

- `--only` and `--skip` **merge** with config (additive union), then intersect
  with the profile allow-list when the profile has one.
- `--baseline` (save mode) does not load an existing baseline for filtering.
- `--no-baseline` disables all baseline loading.
- `--baseline-file` overrides `[codehound.baseline].path`.

---

## Path filters & ignores

| Mechanism | Role |
|-----------|------|
| `include` / `exclude` | Config globs relative to scan roots |
| `exclude_tests` / `--include-tests` | `*_test.*` handling |
| `--exclude-examples` | Skip examples / samples paths |
| `.codehoundignore` | gitignore-style globs in walked directories |
| `.gitignore` / `.ignore` | Honored via the [`ignore`](https://docs.rs/ignore) crate |
| `// codehound-ignore…` | Inline suppressions — [finding-identity.md](./finding-identity.md) |

---

## Environment variables

| Variable | Equivalent |
|----------|------------|
| `CODEHOUND_CONFIG` | `--config` |
| `CODEHOUND_ONLY` | `--only` |
| `CODEHOUND_SKIP` | `--skip` |
| `CODEHOUND_PROFILE` | `--profile` |
| `CODEHOUND_GO` | `go` binary for `--typed` |
| `NO_COLOR` | `--no-color` |
| `RUST_LOG` | Tracing verbosity (not a product flag) |

---

## Writing a starter file

```sh
codehound init
```

Writes the commented template from `templates/codehound.toml` into the current
directory. Exits `2` if `codehound.toml` already exists; exits `3` on write
failure.

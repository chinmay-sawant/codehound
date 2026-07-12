# Configuration (`codehound.toml`)

CodeHound reads an optional `codehound.toml` from the current directory or any
parent directory. All fields are optional and the file may be empty.

Unknown fields are **rejected** with a parse error — there is no silent
fallback for typos. The CLI flags take precedence over config file values
for `--only` and `--skip`; for `--fail-on` (mapped to `FailPolicy`), the CLI
flag also wins when set explicitly.

## Discovery

The lookup walks from the current directory upward:

```
$ pwd
/home/me/projects/myapp

# Tries:
#   ./codehound.toml
#   ../codehound.toml
#   ../../codehound.toml
#   ... up to the filesystem root
```

Override discovery with `--config <PATH>` or `CODEHOUND_CONFIG=<PATH>`.

## Schema

```toml
[codehound]
# Restrict analysis to specific languages. Values: "go", "python".
# languages = ["go", "python"]

# Only run these rule IDs (string-equal match against the detector's rule_ids()).
# only = ["CWE-22", "CWE-89"]

# Skip these rule IDs. Appended to any --skip passed on the CLI.
# skip = ["CWE-15"]

# Failure policy: "none" | "never" | "medium" | "warnings" | "high" | "strict".
# Unknown values are rejected (no silent fallback). CLI --strict / --no-fail /
# --warnings-as-errors always win when set.
# fail_on = "high"

# Glob patterns to include. The default is the language's supported extensions.
# include = ["**/*.go"]

# Glob patterns to exclude. Applied after include.
# exclude = ["**/vendor/**", "**/*_test.go"]

# Baselines are enabled by default and auto-discovered upward from the current
# directory. Configure a custom file path or disable config-driven loading here.
# [codehound.baseline]
# enabled = true
# path = ".codehound-baseline.json"
```

## Precedence (highest to lowest)

1. CLI flags (`--only`, `--skip`, `--strict`, `--no-fail`, `--warnings-as-errors`, `--debug-timing`, `--diagnostics`, `--baseline`, `--no-baseline`, `--baseline-file`)
2. `codehound.toml` values
3. Built-in defaults (no filtering, `fail_on = warnings`)

Note: `--only` and `--skip` are *merged* (additive) — the CLI list extends the
config list. `--fail-on` replaces the config value when the CLI flag is set.
For baselines, `--baseline` save mode ignores config loading, `--no-baseline`
disables all baseline loading, and `--baseline-file` overrides
`[codehound.baseline].path`.

## `.codehoundignore`

A `.codehoundignore` file in any walked directory is honored (gitignore-style
globs). It works alongside `.gitignore` and `.ignore` via the
[`ignore`](https://docs.rs/ignore) crate.

## Environment variables

| Var                  | Equivalent flag |
|----------------------|------------------|
| `CODEHOUND_CONFIG`   | `--config`       |
| `CODEHOUND_ONLY`     | `--only`         |
| `CODEHOUND_SKIP`     | `--skip`         |
| `NO_COLOR`           | `--no-color`     |
| `RUST_LOG`           | verbosity (debug/info/warn) |

## Writing a starter file

```sh
codehound init
```

Writes a commented `codehound.toml` to the current directory if none exists.

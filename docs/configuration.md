# Configuration (`slopguard.toml`)

SlopGuard reads an optional `slopguard.toml` from the current directory or any
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
#   ./slopguard.toml
#   ../slopguard.toml
#   ../../slopguard.toml
#   ... up to the filesystem root
```

Override discovery with `--config <PATH>` or `SLOPGUARD_CONFIG=<PATH>`.

## Schema

```toml
[slopguard]
# Restrict analysis to specific languages. Values: "go", "python".
# languages = ["go", "python"]

# Only run these rule IDs (string-equal match against the detector's rule_ids()).
# only = ["CWE-22", "CWE-89"]

# Skip these rule IDs. Appended to any --skip passed on the CLI.
# skip = ["CWE-15"]

# Failure policy: "none", "high", "strict", or anything else for
# warnings-as-errors. The CLI --strict / --no-fail / --warnings-as-errors
# always win when set.
# fail_on = "high"

# Glob patterns to include. The default is the language's supported extensions.
# include = ["**/*.go"]

# Glob patterns to exclude. Applied after include.
# exclude = ["**/vendor/**", "**/*_test.go"]
```

## Precedence (highest to lowest)

1. CLI flags (`--only`, `--skip`, `--strict`, `--no-fail`, `--warnings-as-errors`)
2. `slopguard.toml` values
3. Built-in defaults (no filtering, `fail_on = warnings`)

Note: `--only` and `--skip` are *merged* (additive) — the CLI list extends the
config list. `--fail-on` replaces the config value when the CLI flag is set.

## `.slopguardignore`

A `.slopguardignore` file in any walked directory is honored (gitignore-style
globs). It works alongside `.gitignore` and `.ignore` via the
[`ignore`](https://docs.rs/ignore) crate.

## Environment variables

| Var                  | Equivalent flag |
|----------------------|------------------|
| `SLOPGUARD_CONFIG`   | `--config`       |
| `SLOPGUARD_ONLY`     | `--only`         |
| `SLOPGUARD_SKIP`     | `--skip`         |
| `NO_COLOR`           | `--no-color`     |
| `RUST_LOG`           | verbosity (debug/info/warn) |

## Writing a starter file

```sh
slopguard init
```

Writes a commented `slopguard.toml` to the current directory if none exists.

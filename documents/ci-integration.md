# CI integration

How to run CodeHound in continuous integration, emit SARIF for GitHub Code
Scanning, and adopt the tool on brownfield repos.

Related: [go-recommended-pack.md](./go-recommended-pack.md),
[output-formats.md](./output-formats.md), [cli.md](./cli.md),
[finding-identity.md](./finding-identity.md).

---

## Recommended place in the pipeline

Run CodeHound **after** your existing Go CI:

1. Build / unit tests  
2. `golangci-lint` / staticcheck  
3. `govulncheck` (module CVEs)  
4. **CodeHound** (`--profile recommended`)

CodeHound complements those tools; it does not replace them. See
[go-vs-staticcheck.md](./go-vs-staticcheck.md).

---

## One-liner gate

```bash
codehound --profile recommended --format sarif . > codehound.sarif
```

- Default fail policy under recommended is **strict** (high / critical only).
- S-tier PERF findings are **medium**: they appear in SARIF but do **not** fail
  the job unless you add `--warnings-as-errors`.
- `--strict` is redundant with the recommended profile default; keep it only if
  you want a CLI-explicit override of config `fail_on`.

---

## GitHub Actions (composite action)

This repository ships [`.github/actions/codehound-scan`](../.github/actions/codehound-scan/action.yml):

| Input | Default | Purpose |
|-------|---------|---------|
| `profile` | `recommended` | Scan pack |
| `paths` | `.` | Paths to scan |
| `args` | _(empty)_ | Extra CLI args |
| `sarif-file` | `codehound.sarif` | Output path |
| `upload-sarif` | `true` | Upload to Code Scanning |
| `strict` | `true` | Pass `--strict` |

### Upload-then-fail contract

The action:

1. Runs CodeHound with `--format sarif` and captures the exit code.
2. **Always** attempts SARIF upload when `upload-sarif` is true (so Code Scanning
   still gets results when findings fail the gate).
3. Propagates the scan exit code afterward so the job fails on policy breach.

Minimal workflow sketch:

```yaml
name: codehound
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/codehound-scan
        with:
          profile: recommended
          paths: .
          upload-sarif: "true"
```

Full example: [`.github/workflows/codehound.yml`](../.github/workflows/codehound.yml).

---

## Generic CI (no GitHub)

```bash
codehound --profile recommended --format sarif --sarif-compact . > codehound.sarif
# archive codehound.sarif as a build artifact
# fail the job on exit code 1 (findings) or 2+ (errors)
```

JSON for custom dashboards:

```bash
codehound --format json --json-envelope . > codehound.json
```

---

## Brownfield adoption

1. **Advisory:** `codehound --no-fail --format sarif . > codehound.sarif`  
   Upload SARIF without blocking merges.
2. **Baseline accepted debt:**  
   `codehound --profile recommended --baseline .`  
   Or `codehound baseline save .`
3. **Tighten:** drop `--no-fail`; only new fingerprints fail (or appear).
4. **Hygiene:**  
   `codehound baseline diff .` · `baseline prune .` · `baseline update .`
5. **Local noise:** `// codehound-ignore: PERF-101` (see
   [finding-identity.md](./finding-identity.md)).

---

## Cache in CI

- Cache is **on by default** under `.codehound-cache/`.
- Prefer a **stable cache directory** per job (or restore/save `.codehound-cache`
  between runs) for warm scans.
- Parallel jobs writing the **same** cache directory are not multi-writer safe —
  use distinct `--cache-dir` values or exclusive jobs.
- Do **not** enable `--export-context` / `--export-chunks` on pure gate jobs
  unless you intentionally archive those trees.

Details: [incremental-cache.md](./incremental-cache.md).

---

## Exit codes for CI scripts

| Code | Treat as |
|------|----------|
| `0` | Pass |
| `1` | Policy failure (findings) |
| `2` | Config / CLI mistake |
| `3`–`5` | Scan / parse / engine errors |
| `101` | Panic |

Full table: [output-formats.md](./output-formats.md#exit-codes).

# Output formats

CodeHound emits findings in three formats. Pick with `--format {text|json|sarif}`.

Severity on the wire is always one of:

| Severity | Text color (approx.) | SARIF `level` | `security-severity` |
|----------|----------------------|---------------|---------------------|
| `info` | cyan | `note` | `0.0` |
| `low` | yellow | `warning` | `2.0` |
| `medium` | yellow (bold) | `warning` | `5.0` |
| `high` | red | `error` | `7.5` |
| `critical` | red+bold | `error` | `9.5` |

BP pack findings use a fixed SARIF `security-severity` of `5.0` unless
overridden. Values come from `src/reporting/sarif/log.rs` and
`src/rules/severity.rs` — treat this table as the source of truth for
machine consumers.

Related: [cli.md](./cli.md), [finding-identity.md](./finding-identity.md),
[ci-integration.md](./ci-integration.md).

---

## Text (default)

```text
high  CWE-22  src/handler.go:14:5  user-controlled input reaches a filesystem path sink
  ↳ CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
  fix: validate and normalize the path, then check it stays under the allowed root

critical  CWE-89  src/db.go:9:18  user-controlled input is concatenated into a SQL string

3 findings
  severity: 1 critical, 1 high, 1 info
  top rules: CWE-89 ×1, CWE-22 ×1, CWE-78 ×1
  scan errors: 0
```

- Disable color with `--no-color` or `NO_COLOR=1`.
- `--no-snippet` suppresses the source snippet block.
- `--verbose` shows structured evidence, confidence, tags, and suppression status.
- `--show-fingerprint` prints the stable fingerprint in text.
- `--debug-timing` prints a per-detector timing breakdown after findings.
- Summary footer lists totals by severity and the top 5 rules by count.
- When stats collection is on (`--debug-timing` or `--diagnostics`), the footer
  also shows files scanned, lines scanned, and wall time.

---

## JSON (NDJSON by default)

One finding object per line (stream-friendly):

```json
{"rule_id":"CWE-22","rule_title":"Path traversal","file":"src/handler.go","line":14,"column":5,"message":"...","severity":"high","cwe":[],"fix":null,"fingerprint":"codehound:2:CWE-22:src/handler.go:a1b2c3d4e5f60718"}
```

- `severity` is one of `"info"`, `"low"`, `"medium"`, `"high"`, `"critical"`
  (not `"warning"`).
- `cwe` is always an array (`[]` when empty).
- `fingerprint` is always present and stable across text, JSON, SARIF,
  baselines, and CI diffing.
- Structured detector fields are additive and omitted when unset.

Optional / extended fields (when present):

| Field | Meaning |
|-------|---------|
| `category` | Coarse family (`performance`, `security`, …) |
| `end_line` / `end_column` | Span end when known |
| `byte_offset` / `byte_length` | Byte span when known |
| `snippet` | Source excerpt |
| `evidence` | Machine-readable detector evidence |
| `confidence` | `0.0`–`1.0` when set |
| `tags` | Workflow / category labels |
| `suppressed` | Present when emitted in ignored/suppressed mode |
| `remediation` | Longer fix guidance (vs short `fix`) |

### Envelope mode

```sh
codehound --format json --json-envelope .
```

Wraps findings in a single object with `findingCount`, `errorCount`,
`suppressedCount`, tool/version metadata, and optional `stats` when timing
collection is enabled. Requires `--format json`.

---

## SARIF 2.1.0

```sh
codehound --format sarif ./... > out.sarif
codehound --format sarif --sarif-compact ./... > out.sarif
```

| Field | Value |
|-------|-------|
| `$schema` | `https://json.schemastore.org/sarif-2.1.0.json` |
| `version` | `2.1.0` |
| `tool.driver.name` | `codehound` |
| `tool.driver.informationUri` | repository URL |
| `tool.driver.version` / `semanticVersion` | package version |
| `tool.driver.rules[]` | Rule metadata, sorted by id |
| `invocations[0].executionSuccessful` | `true` if no per-file errors |
| `results[].ruleId` | Stable id (`PERF-*`, `CWE-*`, `BP-*`) |
| `results[].ruleIndex` | Index into `rules` |
| `results[].level` | `note` / `warning` / `error` (see severity table) |
| `results[].locations` | File URI + 1-indexed `startLine` / `startColumn` |
| `partialFingerprints["codehound/v1"]` | Stable fingerprint (`codehound:2:…`) |
| `properties.security-severity` | See severity table (not GitHub’s older 4.0/7.0/9.0 scale) |
| `properties.tags` | Category / CWE tags |
| `properties.remediation` / `codehoundEvidence` | Optional longer guidance and evidence |
| `results[].rank` | confidence × 100 when confidence is set |
| `results[].suppressions[].kind` | `"external"` when suppressed |

Additive `properties` fields are safe for consumers that ignore unknowns.

GitHub Code Scanning upload pattern (upload SARIF even when exit ≠ 0):
[ci-integration.md](./ci-integration.md).

---

## Fail policy vs formats

Reporter choice does **not** change exit policy. SARIF/JSON jobs still exit
non-zero when findings exceed the fail policy — capture the file first, then
fail the job (the composite action does this).

Under `--profile recommended`, medium PERF findings appear in output but do not
fail unless `--warnings-as-errors` is set. See
[go-recommended-pack.md](./go-recommended-pack.md).

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no failing findings, no scan errors |
| `1` | Findings exceeded the `FailPolicy` |
| `2` | Configuration / CLI error |
| `3` | Internal / I/O / encoding error (or scan aborted) |
| `4` | Per-file parse error (tree-sitter) |
| `5` | Per-file detector/engine error |
| `101` | Rust panic in a worker thread |

Per-file scan errors take precedence over finding fail policy when both occur
(`scan_exit_code` in `src/app/run.rs`).

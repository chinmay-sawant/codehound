# Output formats

SlopGuard emits findings in three formats. Pick with `--format {text|json|sarif}`.

## Text (default)

```
high  CWE-22  src/handler.go:14:5  user-controlled input reaches a filesystem path sink
  ↳ CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
  fix: validate and normalize the path, then check it stays under the allowed root

critical  CWE-89  src/db.go:9:18  user-controlled input is concatenated into a SQL string

3 findings
  severity: 1 critical, 1 high, 1 info
  top rules: CWE-89 ×1, CWE-22 ×1, CWE-78 ×1
  scan errors: 0
```

- Severity tokens are color-coded: `cyan` (info), `yellow` (warning),
  `red` (high), `red+bold` (critical). Disable with `--no-color` or
  `NO_COLOR=1`.
- Use `--no-snippet` to suppress the source snippet block.
- Use `--verbose` to show structured evidence summaries, confidence, tags, and suppression status.
- Use `--debug-timing` to print a per-detector timing breakdown after findings.
- CWE list is sorted by id for deterministic output.
- A summary footer lists totals by severity and the top 5 rules by count.
- When stats collection is enabled (`--debug-timing` or `--diagnostics`), the footer also shows files scanned, lines scanned, and total wall time.

## JSON (NDJSON, one finding per line)

```json
{"rule_id":"CWE-22","rule_title":"Path traversal","file":"src/handler.go","line":14,"column":5,"message":"...","severity":"high","cwe":[],"fix":null}
```

- No envelope, no header — stream-friendly.
- `cwe` is always an array (`[]` when no CWE references).
- One JSON object per line; suitable for `jq` pipelines.
- `severity` is one of `"info"`, `"warning"`, `"high"`, `"critical"`.
- `fingerprint` is always present and is stable across text, JSON, SARIF,
  baseline matching, and CI diffing.
- Structured detector fields are additive and omitted when unset, so older
  consumers can keep parsing the core finding shape.
- `--json-envelope` wraps findings in a single object that also includes
  `findingCount`, `errorCount`, `suppressedCount`, and an optional `stats`
  object when timing/stats collection is enabled.

Optional structured fields:

| Field         | Meaning |
|---------------|---------|
| `evidence`    | Machine-readable detector evidence such as `DangerousCall`, `TaintFlow`, `PatternMatch`, `MissingConfig`, or `ControlFlowIssue`. |
| `confidence`  | Detector confidence from `0.0` to `1.0` when a heuristic rule can quantify certainty. |
| `tags`        | Machine-readable labels for workflow hints, false-positive risk, framework context, or detector category. |
| `suppressed`  | Present only when the finding is emitted in ignored/suppressed mode. |
| `remediation` | Longer actionable remediation guidance, separate from the shorter `fix` hint. |

## SARIF 2.1.0

```sh
slopguard --format sarif ./... > out.sarif
```

Or compact (one line, no indentation) for machine consumers:

```sh
slopguard --format sarif --no-snippet ./... | jq > out.sarif
```

The output conforms to
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
and includes:

| Field                                              | Value |
|----------------------------------------------------|-------|
| `$schema`                                          | `https://json.schemastore.org/sarif-2.1.0.json` |
| `version`                                          | `2.1.0` |
| `runs[0].tool.driver.name`                         | `slopguard` |
| `runs[0].tool.driver.informationUri`               | repository URL (from `Cargo.toml`) |
| `runs[0].tool.driver.version`                      | package version (from `Cargo.toml`) |
| `runs[0].tool.driver.semanticVersion`              | same |
| `runs[0].tool.driver.rules[].id`                   | rule id, e.g. `CWE-22` |
| `runs[0].tool.driver.rules[]`                      | sorted alphabetically by id |
| `runs[0].invocations[0].executionSuccessful`       | `true` if no per-file errors |
| `runs[0].invocations[0].endTimeUtc`                | ISO 8601 UTC at scan end |
| `runs[0].invocations[0].workingDirectory.uri`      | `.` |
| `runs[0].results[].ruleId`                         | rule id |
| `runs[0].results[].ruleIndex`                      | index into the `rules` array |
| `runs[0].results[].level`                          | `note` / `warning` / `error` |
| `runs[0].results[].message.text`                   | detector message |
| `runs[0].results[].locations[].physicalLocation.artifactLocation.uri` | file path |
| `runs[0].results[].locations[].physicalLocation.region.startLine`/`startColumn` | 1-indexed |
| `runs[0].results[].partialFingerprints["slopguard/v1"]` | stable fingerprint (`slopguard:1:<rule>:<file>:<line>:<col>`) |
| `runs[0].results[].properties.tags`                | `["security", "cwe", "cwe-22", ...]` |
| `runs[0].results[].properties.security-severity`   | `0.0`/`4.0`/`7.0`/`9.0` |
| `runs[0].results[].rank`                           | confidence × 100 (only when `confidence` is set) |
| `runs[0].results[].suppressions[].kind`            | `"external"` when the finding is suppressed |
| `runs[0].results[].properties.slopguardEvidence`   | full structured detector evidence as JSON |
| `runs[0].results[].properties.remediation`         | longer remediation guidance when set |

New properties are additive and use SARIF's standard `properties` bag, so existing SARIF consumers should ignore unknown fields gracefully.

The `security-severity` mapping follows the
[GitHub Code Scoring scale](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning-alerts#about-severity-levels):

| Severity    | security-severity |
|-------------|-------------------|
| `info`      | `0.0`             |
| `warning`   | `4.0`             |
| `high`      | `7.0`             |
| `critical`  | `9.0`             |

## Exit codes

| Code | Meaning                                                  |
|------|----------------------------------------------------------|
| `0`  | clean (no failing findings, no scan errors)             |
| `1`  | findings exceeded the `FailPolicy`                       |
| `2`  | configuration error (unknown flag, invalid config, etc.) |
| `3`  | internal / I-O / engine error                            |
| `101` | Rust panic (unhandled unwind in a worker thread)         |

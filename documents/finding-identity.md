# Finding identity, ignores, and baselines

CodeHound emits a canonical fingerprint for each finding so JSON, SARIF,
exports, baselines, and CI diffing can refer to the same issue with a stable
identifier.

Related: [cli.md](./cli.md), [configuration.md](./configuration.md),
[ci-integration.md](./ci-integration.md),
[`codehound-baseline.schema.json`](../codehound-baseline.schema.json).

---

## Fingerprint format (v2)

```text
codehound-fingerprint-v2 := codehound:2:<rule_id>:<file>:<msg_hash16>
```

Example:

```text
codehound:2:CWE-22:pkg/handler/user.go:a1b2c3d4e5f60718
```

| Field | Meaning |
|-------|---------|
| `tool_name` | always `codehound` |
| `version` | currently `2` (message-stable) |
| `rule_id` | detector id, e.g. `CWE-22`, `PERF-103` |
| `file` | path as reported, normalized to `/` separators |
| `msg_hash16` | first 16 hex chars of SHA-256 of the finding message |

v2 prefers **message stability** over line/column so pure line shifts with the
same message still match. Location (rule + file + line + column) remains a
**fallback** match for baselines.

### Stability guarantees

| Stable across | Not stable across |
|---------------|-------------------|
| Same fingerprint version, rule, file path, message | File renames |
| Text / JSON / SARIF / baseline / export | Message wording changes |
| Forward-slash path normalization | Fingerprint version bumps (regenerate baselines) |

Unicode normalization is not applied to path components.

---

## Inline ignore directives

Supported on Go `//` and Python `#` comments only (not `/* */`, not string
literals, not golangci `//nolint`).

| Form | Effect |
|------|--------|
| `codehound-ignore: RULES` | Next non-comment line |
| `… code // codehound-ignore: RULES` | Same-line (EOL) |
| `codehound-ignore-file` | Whole file (no rule list = all rules) |
| `codehound-ignore-file: RULES` | Whole file for listed rules |
| `codehound-ignore-start` / `codehound-ignore-end` | Block range |

`RULES` is a comma-separated list of rule IDs (`PERF-101,CWE-22`).

### Parsing edge cases

- File-level directives are scanned in the **first 20 lines**.
- An open `codehound-ignore-start` without `-end` extends to **EOF**.
- Directives are **re-applied on every cache hit** — the cache stores raw
  findings; the current run’s suppression context filters them before report.
- Use `--show-ignored` to emit findings that were suppressed by directives.

```go
// codehound-ignore-file: PERF-101,PERF-103

func handler(w http.ResponseWriter, r *http.Request) {
    // codehound-ignore: PERF-190
    client := &http.Client{} // next line only
    _ = client
}
```

---

## Baseline workflow

Baselines record accepted debt so subsequent scans focus on **new** findings.

### Discovery

- Default file: `.codehound-baseline.json`
- Walks upward from the current directory (stops at project boundary / `.git`
  where implemented)
- Override path: `--baseline-file` or `[codehound.baseline].path`
- Disable: `--no-baseline` or `[codehound.baseline] enabled = false`

### CLI

| Command / flag | Purpose |
|----------------|---------|
| `codehound --baseline .` | Scan, **save** findings as baseline, exit |
| `codehound baseline save [PATH…]` | Same idea via subcommand |
| `codehound baseline list` | List entries (`--path` for file) |
| `codehound baseline update` | Merge current findings into baseline |
| `codehound baseline prune` | Drop entries that no longer match live findings |
| `codehound baseline diff` | Diff live findings vs baseline |
| `--show-baselined` | Emit findings that matched the baseline |
| `--no-baseline` | Ignore baseline file this run |
| `--baseline-file PATH` | Custom baseline path |

### Match algorithm

1. Prefer **fingerprint** equality.
2. Fall back to **location** (rule + file + line + column) when fingerprints
   differ (e.g. after a message tweak).
3. Entries with an **expired** `expires` timestamp (ISO-8601) are ignored.

### Optional entry metadata

Runtime supports optional `reason` and `expires` fields on baseline entries.
There are **no** CLI flags to set them — hand-edit the JSON (or use the library
APIs). The published baseline JSON Schema may lag these optional fields;
runtime is the source of truth.

### Example baseline shape

```json
{
  "version": 1,
  "generated_at": "2026-07-01T12:00:00Z",
  "tool_version": "1.0.0",
  "entries": {
    "codehound:2:PERF-101:cmd/server/main.go:abcdef0123456789": {
      "rule_id": "PERF-101",
      "file": "cmd/server/main.go",
      "line": 40,
      "column": 2,
      "reason": "accepted until Q3 rewrite",
      "expires": "2026-10-01T00:00:00Z"
    }
  }
}
```

### Brownfield recipe

1. Advisory scan: `codehound --no-fail .`
2. Save debt: `codehound --baseline .`
3. Gate PRs on new fingerprints only (default load of baseline).
4. Periodically: `baseline diff` → fix or `update` / `prune`.
5. Local noise: prefer inline `codehound-ignore` for intentional exceptions.

See [ci-integration.md](./ci-integration.md#brownfield-adoption).

---

## Migration

New scans emit the latest fingerprint version. After a version bump, regenerate
baselines to avoid accidental mismatches.

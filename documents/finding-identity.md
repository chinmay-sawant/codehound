# Finding Identity

CodeHound emits a canonical fingerprint for each finding so JSON, SARIF,
exports, baselines, and CI diffing can refer to the same issue with a stable
identifier.

## Format (v2)

```text
codehound-fingerprint-v2 := codehound:2:<rule_id>:<file>:<msg_hash16>
```

Example:

```text
codehound:2:CWE-22:pkg/handler/user.go:a1b2c3d4e5f60718
```

Fields:

- `tool_name`: always `codehound`
- `version`: currently `2` (message-stable)
- `rule_id`: detector rule id, for example `CWE-22` or `SLOP101`
- `file`: file path as CodeHound reports it, normalized to forward slashes
- `msg_hash16`: first 16 hex chars of SHA-256 of the finding message

v2 prefers **message stability** over line/column so pure line shifts with the
same message still match baseline fingerprints. Location
(rule + file + line + column) remains a **fallback** match for baselines.

## Path Rules

Paths are emitted with `/` separators on all platforms. CodeHound does not apply
Unicode normalization to file names; it preserves the path string surfaced by the
scan pipeline after separator normalization.

## Stability

Fingerprints are stable across repeated runs of the same fingerprint version
over the same rule, file, and message. They are not stable across file renames
or message wording changes. Regenerate baselines after fingerprint version bumps.

## Migration

New scans emit the latest fingerprint version. When versions change, regenerate
baselines to avoid accidental mismatches.

## Suppression and the incremental cache

Supported ignore directives (Go `//` and Python `#` comments):

| Form | Effect |
|------|--------|
| `codehound-ignore: RULES` | Next non-comment line |
| `… code // codehound-ignore: RULES` | Same-line (EOL) |
| `codehound-ignore-file[: RULES]` | Whole file (header) |
| `codehound-ignore-start` / `-end` | Block range |

**Non-goal:** golangci `//nolint` aliases are not accepted — use `codehound-ignore`.

Directives are re-applied on every cache hit. The cache stores raw findings; the
current run's suppression context filters them before report.

## Baseline identity

Optional entry fields: `reason`, `expires` (ISO-8601).

CLI: `codehound baseline list|prune|update|diff|save` and `--show-baselined`.

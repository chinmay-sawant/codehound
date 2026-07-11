# Finding Identity

CodeHound emits a canonical fingerprint for each finding so JSON, SARIF,
exports, future baselines, and CI diffing can refer to the same issue with the
same stable identifier.

## Format

```text
codehound-fingerprint-v1 := <tool_name>:<version>:<rule_id>:<file>:<line>:<column>
```

Example:

```text
codehound:1:CWE-22:pkg/handler/user.go:42:5
```

Fields:

- `tool_name`: always `codehound`
- `version`: currently `1`
- `rule_id`: detector rule id, for example `CWE-22` or `SLOP101`
- `file`: file path as CodeHound reports it, normalized to forward slashes
- `line`: 1-indexed start line
- `column`: 1-indexed start column

The fingerprint intentionally excludes message text, severity, function names,
and byte offsets. Those fields can change as rules improve or code shifts, while
the v1 identity is scoped to the rule and reported source location.

## Path Rules

Paths are emitted with `/` separators on all platforms. CodeHound does not apply
Unicode normalization to file names; it preserves the path string surfaced by the
scan pipeline after separator normalization.

Project-relative paths are preferred when the scanner is invoked with
project-relative inputs. Absolute paths remain absolute if that is what the
scan pipeline reports.

## Stability

Fingerprints are stable across repeated runs of the same CodeHound fingerprint
version over the same file and location. They are not stable across file renames,
line or column shifts, or future fingerprint format changes.

A breaking change to the fields, field order, separator normalization, or
meaning of any field requires a fingerprint version bump.

## Migration

New scans emit the latest fingerprint version. Future baseline or cache readers
should treat unknown versions as incompatible unless an explicit migration path
exists. When fingerprint versions change, users should regenerate baselines to
avoid accidental mismatches.

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

Fingerprints are `codehound:2:RULE:file:msg_hash` (message-stable; line drift
resilient when the message is unchanged). Location (rule+file+line+col) remains
a fallback for matching. Optional entry fields: `reason`, `expires` (ISO-8601).

CLI: `codehound baseline list|prune|update|diff|save` and `--show-baselined`.

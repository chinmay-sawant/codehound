# Finding Identity

SlopGuard emits a canonical fingerprint for each finding so JSON, SARIF,
exports, future baselines, and CI diffing can refer to the same issue with the
same stable identifier.

## Format

```text
slopguard-fingerprint-v1 := <tool_name>:<version>:<rule_id>:<file>:<line>:<column>
```

Example:

```text
slopguard:1:CWE-22:pkg/handler/user.go:42:5
```

Fields:

- `tool_name`: always `slopguard`
- `version`: currently `1`
- `rule_id`: detector rule id, for example `CWE-22` or `SLOP101`
- `file`: file path as SlopGuard reports it, normalized to forward slashes
- `line`: 1-indexed start line
- `column`: 1-indexed start column

The fingerprint intentionally excludes message text, severity, function names,
and byte offsets. Those fields can change as rules improve or code shifts, while
the v1 identity is scoped to the rule and reported source location.

## Path Rules

Paths are emitted with `/` separators on all platforms. SlopGuard does not apply
Unicode normalization to file names; it preserves the path string surfaced by the
scan pipeline after separator normalization.

Project-relative paths are preferred when the scanner is invoked with
project-relative inputs. Absolute paths remain absolute if that is what the
scan pipeline reports.

## Stability

Fingerprints are stable across repeated runs of the same SlopGuard fingerprint
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

`// slopguard-ignore: RULE_ID` and `// slopguard-ignore-file` directives are
re-applied on every cache hit. The cache stores the raw findings; the current
run's suppression context filters them before they are reported. This means a
finding suppressed after the first scan is dropped on the next warm-cache run
even though the file content hash has not changed.

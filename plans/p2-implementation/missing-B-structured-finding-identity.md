# Missing B — Structured Finding Identity as First-Class Output

> **Parent:** `plans/p2.md` — Missing Item B
> **Status:** Phase 1, Phase 2 JSON/SARIF/export emission, Phase 3 baseline consumption, Phase 4 stability docs/tests, and Phase 5 caller audit landed. Canonical fingerprints now use `slopguard:1:<rule_id>:<file>:<line>:<column>` through the shared `Fingerprint` type. Incremental/cache consumers and optional terminal display remain open.
> **Estimated effort:** 3-5 days.

---

## Overview

Baseline, deduplication, ignore-once, and CI diffing all need the same stable identity semantics. The `fingerprint()` method exists but is not yet elevated into the product contract across all output paths.

---

## Phase 1: Define Canonical Finding Identity Format

### 1.1 Design the fingerprint v1 specification

- [x] Document the fingerprint format contract:
  ```
  slopguard-fingerprint-v1 := <tool_name>:<version>:<rule_id>:<file>:<line>:<column>
  ```
- [x] Example: `slopguard:1:CWE-22:pkg/handler/user.go:42:5`
- [x] Version the format: embed `v1` or `1` so future changes can be detected
- [x] Decide what goes into the identity:
  - [x] `rule_id` — required (identifies which check found it)
  - [x] `file` — required (relative path from project root)
  - [x] `line` — required (1-indexed)
  - [x] `column` — required (1-indexed)
  - [x] What about `message`? — NOT included (message text may change between versions)
  - [x] What about `severity`? — NOT included (severity may be tuned)
  - [x] What about `function`? — NOT included (functions can be renamed)
  - [x] What about `byte_offset`? — NOT included (redundant with line:col)
- [x] Document edge cases:
  - [x] File path normalization: use forward slashes on all platforms (`/` not `\`)
  - [x] File path relativity: relative to the project root (where `.slopguard.toml` or `.git` lives)
  - [x] Unicode file paths: use the OS-native representation (bytes, not normalized Unicode)
- [x] Create `docs/finding-identity.md` with the full specification

### 1.2 Create canonical `Fingerprint` type

- [x] Define `Fingerprint` in `src/rules/fingerprint.rs`:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
  pub struct Fingerprint {
      pub tool: String,       // "slopguard"
      pub version: u32,       // 1
      pub rule_id: String,
      pub file: String,
      pub line: usize,
      pub column: usize,
  }
  ```
- [x] Implement `Fingerprint::from_finding(finding: &Finding) -> Self`
  - [x] Normalize file path (forward slashes)
  - [x] Use `finding.rule_id`, `finding.file`, `finding.line`, `finding.column`
- [x] Implement `Fingerprint::to_string() -> String`
  - [x] Format: `slopguard:1:<rule_id>:<file>:<line>:<column>`
- [x] Implement `Fingerprint::parse(s: &str) -> Result<Self>` for deserialization
- [x] Implement `Display` for `Fingerprint`
- [x] Replace `Finding::fingerprint()` with a method that creates a `Fingerprint`:
  ```rust
  pub fn fingerprint(&self) -> Fingerprint {
      Fingerprint::from_finding(self)
  }
  ```
- [x] Keep string-based output as a convenience:
  ```rust
  pub fn fingerprint_string(&self) -> String {
      self.fingerprint().to_string()
  }
  ```

---

## Phase 2: Emit Fingerprint in All Output Formats

### 2.1 JSON output

- [x] In `src/reporting/json.rs`:
  - [x] Add `fingerprint` field to `FindingJson` struct (already existed; now it calls `fingerprint_string()` from the new `Fingerprint` type)
  - [x] Ensure the serialized value is the canonical string: `slopguard:1:CWE-22:file.go:42:5`
  - [x] Add unit test: serialization preserves fingerprint format
- [x] Ensure `--json-envelope` mode also includes fingerprint

### 2.2 SARIF output

- [x] In `src/reporting/sarif.rs` (line 199-208):
  - [x] Update `partialFingerprints` to use the canonical format
  - [x] Current format: `<version>:<rule_id>:<file>:<line>:<column>`
  - [x] New format: `slopguard:1:<rule_id>:<file>:<line>:<column>` (add tool name prefix)
  - [ ] Add `primary` or `fullyQualifiedLogicalName` if SARIF spec supports it
  - [x] Document the fingerprint key: `slopguard/v1`
  - [x] Add unit test: SARIF output contains `partialFingerprints.slopguard/v1` with correct value

### 2.3 Export layer

- [x] In `src/export/mod.rs`:
  - [x] Include the canonical fingerprint in each context `.txt` file
  - [x] Format: `Fingerprint: slopguard:1:CWE-22:pkg/handler/user.go:42:5`
  - [x] Include in chunk files too (for machine parsing)

### 2.4 Text/terminal output

- [ ] In `src/reporting/text.rs`:
  - [ ] Optionally show fingerprint in verbose mode: `--verbose` or `--show-fingerprint`
  - [ ] Default: don't show (text output is for humans)
  - [ ] Add CLI flag: `--show-fingerprint`

---

## Phase 3: Consume Fingerprint in Feature Code

### 3.1 Baseline (P2.2)

- [x] In `src/engine/baseline.rs` (new file from P2.2 plan):
  - [x] Use `Fingerprint` type for baseline entries
  - [x] Store fingerprints in the baseline file
  - [x] Match findings against baseline using `Fingerprint` equality
  - [x] Documentation: baseline file stores `"fingerprint"` field with canonical fingerprint string

### 3.2 Incremental analysis (P2.3)

- [ ] In cache entries, store fingerprints alongside findings
- [ ] Use fingerprints for cache deduplication/verification (if two findings have the same fingerprint, they're the same finding regardless of message text changes)

### 3.3 Inline ignore (P2.2)

- [x] In `src/engine/ignore.rs` (new file from P2.2 plan):
  - [x] Parse ignore comments by rule ID (not full fingerprint)
  - [x] When matching, compare `finding.rule_id` against the ignore directive
  - [x] Fingerprint not directly needed for inline ignore (it's rule-level, not finding-level)

### 3.4 CI diffing (future)

- [ ] Future CI integration can diff two runs by comparing `Fingerprint` sets
  - [ ] New findings = fingerprints in run2 but not in run1
  - [ ] Fixed findings = fingerprints in run1 but not in run2
- [ ] This is a natural consequence of having fingerprints in JSON output

---

## Phase 4: Stability Guarantees

### 4.1 Fingerprint stability contract

- [x] Document the stability guarantees in `docs/finding-identity.md`:
  - [x] Fingerprints are stable across runs of the same tool version on the same file
  - [x] Fingerprints are NOT stable across tool versions (version is embedded)
  - [x] Fingerprints are NOT stable across file renames (file path is part of identity)
  - [x] Fingerprints are NOT stable across code changes on the same line (column may shift)
- [x] Define what constitutes a "breaking change" to fingerprint format:
  - [x] Changing the format string → version bump
  - [x] Adding/removing fields → version bump
  - [x] Normalizing file paths differently → version bump

### 4.2 Version migration

- [x] Document migration strategy for fingerprint format changes:
  - [x] Baseline/cache readers should accept known versions only
  - [x] New scans should emit the latest fingerprint version
  - [x] Unknown versions should require an explicit migration or re-baseline
  - [x] Document this in `docs/finding-identity.md`

### 4.3 Tests for fingerprint stability

- [x] Create `tests/rules_fingerprint.rs`:
  - [x] Test: `Fingerprint::from_finding()` produces deterministic output
    - [x] Same finding → same fingerprint every time
  - [x] Test: Two different findings on the same line but different columns → different fingerprints
  - [x] Test: Same logical finding in two different files → different fingerprints
  - [x] Test: `Fingerprint::parse()` round-trips correctly
  - [x] Test: Fingerprint never contains platform-specific path separators (`\` on Windows → `/`)
  - [x] Test: Fingerprint handles Unicode file paths (OS-native bytes)
  - [x] Test: Fingerprint string format matches the documented specification exactly

---

## Phase 5: Migration Path (if breaking changes to existing fingerprint)

### 5.1 Check current fingerprint usage

- [x] Audit all callers of `Finding::fingerprint()`:
  - [x] `src/reporting/json.rs:133` — `FindingJson.fingerprint` field now uses `fingerprint_string()`
  - [x] `src/reporting/sarif.rs:199-208` — `partialFingerprints` map now uses `fingerprint_string()`
  - [x] Any tests referencing fingerprint string format were updated
- [x] If existing fingerprint format changes, document backward-compat need:
  - [x] Old format: `CWE-22:file.go:42:5` (no tool prefix, no version)
  - [x] New format: `slopguard:1:CWE-22:file.go:42:5`
  - [ ] Old baseline/cache files with old format → warn and treat as v0 (compatibility mode; deferred until migration support is implemented)

---

## Dependencies

- `src/rules/finding.rs` — `Finding` struct and `fingerprint()` method
- `src/reporting/json.rs` — JSON output includes fingerprint field
- `src/reporting/sarif.rs` — SARIF output includes `partialFingerprints`
- `src/export/mod.rs` — export context/chunk files
- `src/reporting/text.rs` — optional verbose fingerprint display
- Future: `src/engine/baseline.rs` (P2.2) — baseline matching by fingerprint
- Future: `src/engine/cache.rs` (P2.3) — cache entries include fingerprints

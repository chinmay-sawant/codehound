# Missing B — Structured Finding Identity as First-Class Output

> **Parent:** `plans/p2.md` — Missing Item B
> **Status:** `Finding::fingerprint()` exists and SARIF emits a partial fingerprint, but there is no unified contract across all output formats and future baseline workflows.
> **Estimated effort:** 3-5 days.

---

## Overview

Baseline, deduplication, ignore-once, and CI diffing all need the same stable identity semantics. The `fingerprint()` method exists but is not yet elevated into the product contract across all output paths.

---

## Phase 1: Define Canonical Finding Identity Format

### 1.1 Design the fingerprint v1 specification

- [ ] Document the fingerprint format contract:
  ```
  slopguard-fingerprint-v1 := <tool_name>:<version>:<rule_id>:<file>:<line>:<column>
  ```
- [ ] Example: `slopguard:1:CWE-22:pkg/handler/user.go:42:5`
- [ ] Version the format: embed `v1` or `1` so future changes can be detected
- [ ] Decide what goes into the identity:
  - [ ] `rule_id` — required (identifies which check found it)
  - [ ] `file` — required (relative path from project root)
  - [ ] `line` — required (1-indexed)
  - [ ] `column` — required (1-indexed)
  - [ ] What about `message`? — NOT included (message text may change between versions)
  - [ ] What about `severity`? — NOT included (severity may be tuned)
  - [ ] What about `function`? — NOT included (functions can be renamed)
  - [ ] What about `byte_offset`? — NOT included (redundant with line:col)
- [ ] Document edge cases:
  - [ ] File path normalization: use forward slashes on all platforms (`/` not `\`)
  - [ ] File path relativity: relative to the project root (where `.slopguard.toml` or `.git` lives)
  - [ ] Unicode file paths: use the OS-native representation (bytes, not normalized Unicode)
- [ ] Create `docs/finding-identity.md` with the full specification

### 1.2 Create canonical `Fingerprint` type

- [ ] Define `Fingerprint` in `src/rules/finding.rs` (or a new `src/rules/fingerprint.rs`):
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
- [ ] Implement `Fingerprint::from_finding(finding: &Finding) -> Self`
  - [ ] Normalize file path (forward slashes)
  - [ ] Use `finding.rule_id`, `finding.file`, `finding.line`, `finding.column`
- [ ] Implement `Fingerprint::to_string() -> String`
  - [ ] Format: `slopguard:1:<rule_id>:<file>:<line>:<column>`
- [ ] Implement `Fingerprint::parse(s: &str) -> Result<Self>` for deserialization
- [ ] Implement `Display` for `Fingerprint`
- [ ] Replace `Finding::fingerprint()` with a method that creates a `Fingerprint`:
  ```rust
  pub fn fingerprint(&self) -> Fingerprint {
      Fingerprint::from_finding(self)
  }
  ```
- [ ] Deprecate the old string-based `fingerprint()` or keep it as a convenience:
  ```rust
  pub fn fingerprint_string(&self) -> String {
      self.fingerprint().to_string()
  }
  ```

---

## Phase 2: Emit Fingerprint in All Output Formats

### 2.1 JSON output

- [ ] In `src/reporting/json.rs`:
  - [ ] Add `fingerprint` field to `FindingJson` struct (already exists at line 133 — verify it calls the new `Fingerprint` type)
  - [ ] Ensure the serialized value is the canonical string: `slopguard:1:CWE-22:file.go:42:5`
  - [ ] Add unit test: round-trip serialization preserves fingerprint format
- [ ] Ensure `--json-envelope` mode also includes fingerprint

### 2.2 SARIF output

- [ ] In `src/reporting/sarif.rs` (line 199-208):
  - [ ] Update `partialFingerprints` to use the canonical format
  - [ ] Current format: `<version>:<rule_id>:<file>:<line>:<column>`
  - [ ] New format: `slopguard:1:<rule_id>:<file>:<line>:<column>` (add tool name prefix)
  - [ ] Add `primary` or `fullyQualifiedLogicalName` if SARIF spec supports it
  - [ ] Document the fingerprint key: `slopguard/v1`
  - [ ] Add unit test: SARIF output contains `partialFingerprints.slopguard/v1` with correct value

### 2.3 Export layer

- [ ] In `src/export/mod.rs`:
  - [ ] Include the canonical fingerprint in each context `.txt` file
  - [ ] Format: `Fingerprint: slopguard:1:CWE-22:pkg/handler/user.go:42:5`
  - [ ] Include in chunk files too (for machine parsing)

### 2.4 Text/terminal output

- [ ] In `src/reporting/text.rs`:
  - [ ] Optionally show fingerprint in verbose mode: `--verbose` or `--show-fingerprint`
  - [ ] Default: don't show (text output is for humans)
  - [ ] Add CLI flag: `--show-fingerprint`

---

## Phase 3: Consume Fingerprint in Feature Code

### 3.1 Baseline (P2.2)

- [ ] In `src/engine/baseline.rs` (new file from P2.2 plan):
  - [ ] Use `Fingerprint` type for baseline entries
  - [ ] Store fingerprints in the baseline file
  - [ ] Match findings against baseline using `Fingerprint` equality
  - [ ] Documentation: baseline file stores `"fingerprint"` field with canonical fingerprint string

### 3.2 Incremental analysis (P2.3)

- [ ] In cache entries, store fingerprints alongside findings
- [ ] Use fingerprints for cache deduplication/verification (if two findings have the same fingerprint, they're the same finding regardless of message text changes)

### 3.3 Inline ignore (P2.2)

- [ ] In `src/engine/ignore.rs` (new file from P2.2 plan):
  - [ ] Parse ignore comments by rule ID (not full fingerprint)
  - [ ] When matching, compare `finding.rule_id` against the ignore directive
  - [ ] Fingerprint not directly needed for inline ignore (it's rule-level, not finding-level)

### 3.4 CI diffing (future)

- [ ] Future CI integration can diff two runs by comparing `Fingerprint` sets
  - [ ] New findings = fingerprints in run2 but not in run1
  - [ ] Fixed findings = fingerprints in run1 but not in run2
- [ ] This is a natural consequence of having fingerprints in JSON output

---

## Phase 4: Stability Guarantees

### 4.1 Fingerprint stability contract

- [ ] Document the stability guarantees in `docs/finding-identity.md`:
  - [ ] Fingerprints are stable across runs of the same tool version on the same file
  - [ ] Fingerprints are NOT stable across tool versions (version is embedded)
  - [ ] Fingerprints are NOT stable across file renames (file path is part of identity)
  - [ ] Fingerprints are NOT stable across code changes on the same line (column may shift)
- [ ] Define what constitutes a "breaking change" to fingerprint format:
  - [ ] Changing the format string → version bump
  - [ ] Adding/removing fields → version bump
  - [ ] Normalizing file paths differently → version bump

### 4.2 Version migration

- [ ] Define migration strategy for fingerprint format changes:
  - [ ] Old baseline files with v1 fingerprints: can still be loaded
  - [ ] New scans produce v2 fingerprints
  - [ ] v2 fingerprints won't match v1 baseline entries → baseline user must re-baseline
  - [ ] Document this in release notes

### 4.3 Tests for fingerprint stability

- [ ] Create `tests/rules_fingerprint.rs`:
  - [ ] Test: `Fingerprint::from_finding()` produces deterministic output
    - [ ] Same finding → same fingerprint every time
  - [ ] Test: Two different findings on the same line but different columns → different fingerprints
  - [ ] Test: Same logical finding in two different files → different fingerprints
  - [ ] Test: `Fingerprint::parse()` round-trips correctly
  - [ ] Test: Fingerprint never contains platform-specific path separators (`\` on Windows → `/`)
  - [ ] Test: Fingerprint handles Unicode file paths (OS-native bytes)
  - [ ] Test: Fingerprint string format matches the documented specification exactly

---

## Phase 5: Migration Path (if breaking changes to existing fingerprint)

### 5.1 Check current fingerprint usage

- [ ] Audit all callers of `Finding::fingerprint()`:
  - [ ] `src/reporting/json.rs:133` — `FindingJson.fingerprint` field
  - [ ] `src/reporting/sarif.rs:199-208` — `partialFingerprints` map
  - [ ] Any tests referencing fingerprint string format
- [ ] If existing fingerprint format changes, add backward-compat:
  - [ ] Old format: `CWE-22:file.go:42:5` (no tool prefix, no version)
  - [ ] New format: `slopguard:1:CWE-22:file.go:42:5`
  - [ ] Old baseline/cache files with old format → warn and treat as v0 (compatibility mode)

---

## Dependencies

- `src/rules/finding.rs` — `Finding` struct and `fingerprint()` method
- `src/reporting/json.rs` — JSON output includes fingerprint field
- `src/reporting/sarif.rs` — SARIF output includes `partialFingerprints`
- `src/export/mod.rs` — export context/chunk files
- `src/reporting/text.rs` — optional verbose fingerprint display
- Future: `src/engine/baseline.rs` (P2.2) — baseline matching by fingerprint
- Future: `src/engine/cache.rs` (P2.3) — cache entries include fingerprints

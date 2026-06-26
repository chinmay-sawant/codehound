# P2.2 — Baseline / Ignore-Once Mechanism

> **Parent:** `plans/p2.md` — P2.2
> **Status:** Baseline file core/schema, CLI flags, config integration, save/load workflow, finding filtering, inline `slopguard-ignore` next-line comments, file-level `slopguard-ignore-file`, `--show-ignored`, suppressed-count reporting, and baseline/ignore tests are implemented. File-level skip-before-analysis optimization, shared test helper cleanup, and large-baseline performance validation remain open.
> **Estimated effort:** 1-2 weeks.

---

## Overview

Enable adoption on legacy codebases: first-run baseline captures all current findings, subsequent runs only report new findings. Inline suppression via `// slopguard-ignore:` comments.

---

## Phase 1: Baseline File Format & Core Struct

### 1.1 Define baseline file format

- [x] Create `.slopguard-baseline.json` schema
- [x] Format: JSON object with version and entries
  ```json
  {
    "version": "1",
    "generated_at": "2026-06-10T12:00:00Z",
    "tool_version": "0.1.0",
    "entries": {
      "CWE-22": [
        { "file": "pkg/handler/user.go", "line": 42, "column": 5, "fingerprint": "slopguard:1:CWE-22:pkg/handler/user.go:42:5" }
      ],
      "PERF-1": [
        { "file": "pkg/service/auth.go", "line": 128, "column": 2, "fingerprint": "slopguard:1:PERF-1:pkg/service/auth.go:128:2" }
      ]
    }
  }
  ```
- [x] Use `fingerprint` field as the canonical identity (reuse `Finding::fingerprint_string()` from `src/rules/finding.rs`)
- [x] Group entries by `rule_id` for efficient lookup
- [x] Include version for future format migrations
- [x] Include `tool_version` for compatibility checks

### 1.2 Implement `Baseline` struct

- [x] Create `src/engine/baseline.rs`
- [x] Define `BaselineEntry`:
  ```rust
  struct BaselineEntry {
      file: String,
      line: usize,
      column: usize,
      fingerprint: String,
  }
  ```
- [x] Define `Baseline`:
  ```rust
  struct Baseline {
      version: String,
      generated_at: String,
      tool_version: String,
      entries: HashMap<String, Vec<BaselineEntry>>,  // rule_id → entries
      fingerprint_index: HashSet<String>,             // fast contains lookup
  }
  ```
- [x] Implement `Baseline::from_findings(findings: &[Finding]) -> Baseline`
  - [x] Group findings by `rule_id`
  - [x] Create `BaselineEntry` for each finding with `file`, `line`, `column`, `fingerprint`
- [x] Implement `Baseline::contains(rule_id: &str, file: &str, line: usize, column: usize) -> bool`
  - [x] First check `fingerprint_index` for fast lookup: `slopguard:1:<rule_id>:<file>:<line>:<column>`
  - [x] Fall back to scanning entries for the rule_id if needed
- [x] Implement `Baseline::from_file(path: &Path) -> Result<Baseline>`
  - [x] Read JSON file, deserialize, build `fingerprint_index`
- [x] Implement `Baseline::to_file(&self, path: &Path) -> Result<()>`
  - [x] Serialize to JSON with pretty-printing, write to path
- [x] Register `baseline.rs` module in `src/engine/mod.rs`:
  - [x] module registered and exported via `pub use`

### 1.3 File discovery

- [x] Implement `discover_baseline(cwd: &Path) -> Option<PathBuf>`
  - [x] Walk upward from `cwd` looking for `.slopguard-baseline.json`
  - [x] Stop at filesystem root or when `.git` directory is found
  - [x] Return first match (closest to cwd)
- [x] Respect `.slopguardignore` (already handled by the `ignore` crate in the source walk; baseline discovery does not change source walking)

---

## Phase 2: CLI Flags

### 2.1 Add `--baseline` CLI flag

- [x] Add to `Cli` struct in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "baseline", help = "Save current findings as the baseline (writes .slopguard-baseline.json)")]
  pub baseline: bool,
  ```
- [x] Add to `cli.generate_baseline()` accessor

### 2.2 Add `--no-baseline` CLI flag

- [x] Add to `Cli` struct:
  ```rust
  #[arg(long = "no-baseline", help = "Ignore any existing .slopguard-baseline.json file")]
  pub no_baseline: bool,
  ```
- [x] Lower priority than `--baseline` (if both set, `--baseline` wins)

### 2.3 Add `--baseline-file` CLI flag

- [x] Add to `Cli` struct:
  ```rust
  #[arg(long = "baseline-file", help = "Path to a custom baseline file")]
  pub baseline_file: Option<PathBuf>,
  ```

### 2.4 Update `ScanContext`

- [x] Do not add `baseline: Option<Baseline>` to `ScanContext`; baseline loading/filtering is app-level.
- [x] Do not update `ScanContext::create()` for baseline data.
- [x] Or: keep baseline loaded separately — implemented as app-level load/filter after analysis, keeping `ScanContext` unchanged.

---

## Phase 3: Baseline Integration into Scan Pipeline

### 3.1 Load baseline in `app.rs`

- [x] In `app::run()` (`src/app/`), after `analyze_paths()`:
  - [x] If `--baseline` flag: save findings as baseline file, print "Baseline saved with N entries" and exit 0
  - [x] If not `--no-baseline`:
    - [x] Discover baseline file via `discover_baseline()`
    - [x] If found, load it with `Baseline::from_file()`
    - [x] Print "Using baseline with N entries from <path>" to stderr so JSON/SARIF stdout stays parseable
- [x] If `--baseline-file` is set, use that path instead of discovery

### 3.2 Filter findings against baseline

- [x] After `analyze_paths()` returns `AnalysisResult` and before reporting:
  - [x] If baseline is loaded, filter `result.findings`:
    ```rust
    result.findings.retain(|f| !baseline.contains(f.rule_id, &f.file, f.line, f.column));
    ```
  - [x] Count suppressed findings for reporting
- [x] Add `suppressed_count: usize` field to `AnalysisResult` (`src/engine/result.rs`)
- [x] Update all reporters (`text.rs`, `json.rs`, `sarif.rs`) to show/emit suppressed count

### 3.3 Exit code behavior

- [x] When baseline is active:
  - [x] New (non-baseline) findings → non-zero exit (existing policy)
  - [x] All findings suppressed by baseline → exit 0
  - [x] Errors → exit 3 (unchanged)
- [x] When `--baseline` is used (save mode):
  - [x] Always exit 0, even if current findings exist (they're being acknowledged)

### 3.4 Edge cases

- [x] Empty baseline file (no historical findings): load as empty, no filtering
- [x] Baseline file for different codebase (files don't match): all findings are new, no filtering
- [x] Corrupted baseline JSON: warn and proceed without filtering (graceful degradation)
- [x] Baseline from older tool version: check `tool_version`, warn if major mismatch, use anyway
- [x] Baseline entry format migration: if `version` != "1", warn and skip

---

## Phase 4: Inline Suppression Comments

### 4.1 Define suppression comment format

- [x] Single-rule suppression: `// slopguard-ignore: CWE-22`
  - [x] Applies to the next non-comment line (the finding's line)
- [x] Multi-rule suppression: `// slopguard-ignore: CWE-22, CWE-78`
  - [x] Comma-separated, optional spaces
- [x] All-rules suppression: `// slopguard-ignore: all`
  - [x] Suppresses all findings on the target line
- [x] Block-scope suppression (future): not in initial scope

### 4.2 Implement comment parsing

- [x] Create `src/engine/ignore.rs`
  - [x] `pub fn parse_inline_ignores(source: &str) -> HashMap<usize, IgnoreDirective>`
    - [x] Key: 1-indexed target line number
    - [x] `IgnoreDirective { rule_ids: Option<Vec<String>> }` — `None` means "all"
  - [x] Parse `//\s*slopguard-ignore:\s*(.+)$`-equivalent lines without adding a regex dependency
  - [x] Parse the capture group: split by comma, trim whitespace
  - [x] If captures "all", set `rule_ids = None`
- [x] Register `ignore.rs` in `src/engine/mod.rs`

### 4.3 Integrate into scan pipeline

- [x] In `scan_entry()` (`src/engine/walk.rs:135-197`), after parsing and producing findings:
  - [x] Call `parse_inline_ignores(&source)` to get ignore map
  - [x] Before appending findings to result, filter out any where:
    - [x] The finding's line has an ignore directive
    - [x] And the ignore directive either covers all rules or includes the finding's rule_id
- [x] OR: In `AnalysisResult` filtering (same place as baseline filtering):
  - [x] Not selected; inline filtering happens per file in `scan_entry()` and contributes to `AnalysisResult.suppressed_count`

### 4.4 Implement `// slopguard-ignore-file` for entire-file suppression

- [x] Parse `// slopguard-ignore-file` at the top of a file (within first N lines, e.g., 20)
- [x] Parse `// slopguard-ignore-file: CWE-22, CWE-78` for file-level rule-specific suppression
- [x] Parse `// slopguard-ignore-file: all` for all-rule file suppression
- [ ] In `scan_entry()`, skip analysis for suppressed rules entirely (performance win)
  - [x] Fast-path `// slopguard-ignore-file` / `// slopguard-ignore-file: all` when `--show-ignored` is off, returning before detector execution (does not compute per-finding suppressed count)
  - [ ] Rule-specific detector masking while preserving suppressed-count and `--show-ignored` semantics
- [x] Store `file_ignores` in `ScanContext` or a per-run map — not needed; file-level directives are parsed per source file in `scan_entry()` and applied immediately.

### 4.5 Reporting suppressed-by-comment findings

- [x] Don't report inline-suppressed findings unless `--show-ignored` flag is set
- [x] Add `--show-ignored` CLI flag in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "show-ignored", help = "Report findings suppressed by slopguard-ignore comments")]
  pub show_ignored: bool,
  ```
- [x] When `--show-ignored` is set, include suppressed findings but mark them as `severity: Info` with a suffix " (suppressed)"

---

## Phase 5: Configuration Integration

### 5.1 Update `SlopguardConfig`

- [x] Add baseline fields to `SlopguardConfig` in `src/engine/config.rs`:
  ```rust
  pub struct SlopguardConfig {
      // ... existing fields ...
      pub baseline: Option<BaselineConfig>,
  }
  pub struct BaselineConfig {
      pub enabled: bool,         // default: true
      pub path: Option<PathBuf>, // custom path
  }
  ```
- [x] Update `slopguard.schema.json` to include baseline config properties
- [x] Update `templates/slopguard.toml` to include commented-out baseline section

### 5.2 Config precedence

- [x] CLI `--no-baseline` → disables baseline regardless of config
- [x] CLI `--baseline-file` → overrides config `baseline.path`
- [x] CLI `--baseline` → save mode, ignores config
- [x] Config `baseline.enabled = false` → same as `--no-baseline`
- [x] Default (no CLI, no config) → baseline enabled, auto-discovery

---

## Phase 6: Testing

### 6.1 Unit tests for `Baseline`

- [x] Create `tests/engine_baseline.rs`
- [x] Test `Baseline::from_findings()`: serializes correctly
- [x] Test `Baseline::contains()`: true for exact match
- [x] Test `Baseline::contains()`: false for different file
- [x] Test `Baseline::contains()`: false for different line
- [x] Test `Baseline::contains()`: false for different rule
- [x] Test `Baseline::from_file()` / `to_file()` round-trip
- [x] Test empty baseline: contains returns false for everything

### 6.2 Unit tests for inline ignore parsing

- [x] Test `parse_inline_ignores()`:
  - [x] Single rule: `// slopguard-ignore: CWE-22` → line `N`, rule `CWE-22`
  - [x] Multi-rule: `// slopguard-ignore: CWE-22, CWE-89` → both rules
  - [x] All-rules: `// slopguard-ignore: all` → `None` (all)
  - [x] Whitespace variants: `//slopguard-ignore:CWE-22`, `//  slopguard-ignore:  CWE-22  `
  - [x] Non-matching comments ignored: `// some other comment`
  - [x] No panics on empty source, source with only comments
- [x] Test `// slopguard-ignore-file` parsing:
  - [x] Top of file, within first 20 lines
  - [x] After line 20: ignored (not a file-level directive)

### 6.3 Integration tests for baseline workflow

- [x] Create test helper in `tests/helpers/baseline.rs`:
  - [x] `setup_temp_project(fixtures: &[&str]) -> TempProject` — creates project with known fixtures using an in-repo RAII temp helper
  - [x] `run_slopguard(args: &[&str], cwd: &Path) -> output` — runs the binary with args
  - [x] `parse_findings(output: &str) -> Vec<FindingStub>` — parses JSON output
- [x] Test scenario: Initial baseline save
  - [x] Run scan on project with known findings
  - [x] Run with `--baseline`
  - [x] Assert `.slopguard-baseline.json` created with correct entry count
  - [x] Assert exit code 0
- [x] Test scenario: Baseline suppression
  - [x] Run scan with baseline file present (no changes to code)
  - [x] Assert 0 findings reported
  - [x] Assert exit code 0
- [x] Test scenario: New finding not in baseline
  - [x] Add new vulnerable code to project
  - [x] Run scan with baseline file present
  - [x] Assert only the new finding is reported
  - [x] Assert exit code non-zero (per fail policy)
- [x] Test scenario: `--no-baseline`
  - [x] Run scan with `--no-baseline` even though baseline file present
  - [x] Assert all findings reported (including baseline ones)
- [x] Test scenario: `--baseline-file <custom_path>`
  - [x] Use custom path for baseline file
  - [x] Assert baseline loaded from custom path

### 6.4 Integration tests for inline suppression

- [x] Create fixture `tests/fixtures/go/baseline/suppressed_inline.txt` (materialized to `.go` at test time):
  ```text
  # suppressed inline-ignore fixture
  lang: go
  file: suppressed_inline.go
  ---
  package main

  import (
      "os/exec"
      "net/http"
  )

  func handler(w http.ResponseWriter, r *http.Request) {
      cmd := r.URL.Query().Get("cmd")
      // slopguard-ignore: CWE-78
      exec.Command("sh", "-c", cmd).Run()
  }
  ```
- [x] Scan the fixture, assert CWE-78 does NOT fire
- [x] Scan with `--show-ignored`, assert CWE-78 fires but is marked as suppressed
- [x] Create fixture with `// slopguard-ignore: all` — no findings fire
- [x] Create fixture with `// slopguard-ignore-file` — all findings suppressed

### 6.5 Edge case tests

- [x] Baseline file for project with zero findings → works fine
- [x] Baseline file from different project (no matching files) → all findings reported, no crash
- [x] Corrupted baseline file (invalid JSON) → graceful error, scan proceeds unfiltered
- [x] Very large baseline (10k+ entries) → performance stays acceptable (<50ms to load/filter)

---

## Dependencies

- `serde` + `serde_json` (already in Cargo.toml) for baseline serialization
- `chrono` or `time` crate for `generated_at` timestamp (check if already in Cargo.toml; if not, add)
- `regex` crate (already in Cargo.toml) for inline ignore parsing
- Uses `Finding::fingerprint()` from `src/rules/finding.rs:163`
- Uses `AnalysisResult` from `src/engine/result.rs`
- Uses `ScanContext` from `src/core/scan.rs`

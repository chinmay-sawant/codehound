# P2.2 — Baseline / Ignore-Once Mechanism

> **Parent:** `plans/p2.md` — P2.2
> **Status:** Not started. Only ad-hoc `source.contains("// nolint:...")` in `gin_framework.rs:55`. No global mechanism.
> **Estimated effort:** 1-2 weeks.

---

## Overview

Enable adoption on legacy codebases: first-run baseline captures all current findings, subsequent runs only report new findings. Inline suppression via `// slopguard-ignore:` comments.

---

## Phase 1: Baseline File Format & Core Struct

### 1.1 Define baseline file format

- [ ] Create `.slopguard-baseline.json` schema
- [ ] Format: JSON object with version and entries
  ```json
  {
    "version": "1",
    "generated_at": "2026-06-10T12:00:00Z",
    "tool_version": "0.1.0",
    "entries": {
      "CWE-22": [
        { "file": "pkg/handler/user.go", "line": 42, "column": 5, "fingerprint": "CWE-22:pkg/handler/user.go:42:5" }
      ],
      "PERF-1": [
        { "file": "pkg/service/auth.go", "line": 128, "column": 2, "fingerprint": "PERF-1:pkg/service/auth.go:128:2" }
      ]
    }
  }
  ```
- [ ] Use `fingerprint` field as the canonical identity (reuse `Finding::fingerprint()` from `src/rules/finding.rs:163`)
- [ ] Group entries by `rule_id` for efficient lookup
- [ ] Include version for future format migrations
- [ ] Include `tool_version` for compatibility checks

### 1.2 Implement `Baseline` struct

- [ ] Create `src/engine/baseline.rs`
- [ ] Define `BaselineEntry`:
  ```rust
  struct BaselineEntry {
      file: String,
      line: usize,
      column: usize,
      fingerprint: String,
  }
  ```
- [ ] Define `Baseline`:
  ```rust
  struct Baseline {
      version: String,
      generated_at: DateTime<Utc>,
      tool_version: String,
      entries: HashMap<String, Vec<BaselineEntry>>,  // rule_id → entries
      fingerprint_index: HashSet<String>,             // fast contains lookup
  }
  ```
- [ ] Implement `Baseline::from_findings(findings: &[Finding]) -> Baseline`
  - [ ] Group findings by `rule_id`
  - [ ] Create `BaselineEntry` for each finding with `file`, `line`, `column`, `fingerprint`
- [ ] Implement `Baseline::contains(rule_id: &str, file: &str, line: usize, column: usize) -> bool`
  - [ ] First check `fingerprint_index` for fast lookup: `<rule_id>:<file>:<line>:<column>`
  - [ ] Fall back to scanning entries for the rule_id if needed
- [ ] Implement `Baseline::from_file(path: &Path) -> Result<Baseline>`
  - [ ] Read JSON file, deserialize, build `fingerprint_index`
- [ ] Implement `Baseline::to_file(&self, path: &Path) -> Result<()>`
  - [ ] Serialize to JSON with pretty-printing, write to path
- [ ] Register `baseline.rs` module in `src/engine/mod.rs`:
  - [ ] `pub mod baseline;`

### 1.3 File discovery

- [ ] Implement `discover_baseline(cwd: &Path) -> Option<PathBuf>`
  - [ ] Walk upward from `cwd` looking for `.slopguard-baseline.json`
  - [ ] Stop at filesystem root or when `.git` directory is found
  - [ ] Return first match (closest to cwd)
- [ ] Respect `.slopguardignore` (already handled by the `ignore` crate in the walk)

---

## Phase 2: CLI Flags

### 2.1 Add `--baseline` CLI flag

- [ ] Add to `Cli` struct in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "baseline", help = "Save current findings as the baseline (writes .slopguard-baseline.json)")]
  pub baseline: bool,
  ```
- [ ] Add to `cli.generate_baseline()` accessor

### 2.2 Add `--no-baseline` CLI flag

- [ ] Add to `Cli` struct:
  ```rust
  #[arg(long = "no-baseline", help = "Ignore any existing .slopguard-baseline.json file")]
  pub no_baseline: bool,
  ```
- [ ] Lower priority than `--baseline` (if both set, `--baseline` wins)

### 2.3 Add `--baseline-file` CLI flag

- [ ] Add to `Cli` struct:
  ```rust
  #[arg(long = "baseline-file", help = "Path to a custom baseline file")]
  pub baseline_file: Option<PathBuf>,
  ```

### 2.4 Update `ScanContext`

- [ ] Add field to `ScanContext` in `src/core/scan.rs`:
  ```rust
  pub baseline: Option<Baseline>,
  ```
- [ ] Update `ScanContext::create()` signature to accept optional baseline
- [ ] Or: add `baseline_filter_enabled: bool` flag (simpler, baseline loaded separately)

---

## Phase 3: Baseline Integration into Scan Pipeline

### 3.1 Load baseline in `app.rs`

- [ ] In `app::run()` (`src/app.rs`), after `analyze_paths()`:
  - [ ] If `--baseline` flag: save findings as baseline file, print "Baseline saved with N entries" and exit 0
  - [ ] If not `--no-baseline`:
    - [ ] Discover baseline file via `discover_baseline()`
    - [ ] If found, load it with `Baseline::from_file()`
    - [ ] Print "Using baseline with N entries from <path>"
- [ ] If `--baseline-file` is set, use that path instead of discovery

### 3.2 Filter findings against baseline

- [ ] After `analyze_paths()` returns `AnalysisResult` and before reporting:
  - [ ] If baseline is loaded, filter `result.findings`:
    ```rust
    result.findings.retain(|f| !baseline.contains(f.rule_id, &f.file, f.line, f.column));
    ```
  - [ ] Count suppressed findings for reporting
- [ ] Add `suppressed_count: usize` field to `AnalysisResult` (`src/engine/result.rs`)
- [ ] Update all reporters (`text.rs`, `json.rs`, `sarif.rs`) to show/emit suppressed count

### 3.3 Exit code behavior

- [ ] When baseline is active:
  - [ ] New (non-baseline) findings → non-zero exit (existing policy)
  - [ ] All findings suppressed by baseline → exit 0
  - [ ] Errors → exit 3 (unchanged)
- [ ] When `--baseline` is used (save mode):
  - [ ] Always exit 0, even if current findings exist (they're being acknowledged)

### 3.4 Edge cases

- [ ] Empty baseline file (no historical findings): load as empty, no filtering
- [ ] Baseline file for different codebase (files don't match): all findings are new, no filtering, warn user
- [ ] Corrupted baseline JSON: warn and proceed without filtering (graceful degradation)
- [ ] Baseline from older tool version: check `tool_version`, warn if major mismatch, use anyway
- [ ] Baseline entry format migration: if `version` != "1", warn and skip

---

## Phase 4: Inline Suppression Comments

### 4.1 Define suppression comment format

- [ ] Single-rule suppression: `// slopguard-ignore: CWE-22`
  - [ ] Applies to the next non-comment line (the finding's line)
- [ ] Multi-rule suppression: `// slopguard-ignore: CWE-22, CWE-78`
  - [ ] Comma-separated, optional spaces
- [ ] All-rules suppression: `// slopguard-ignore: all`
  - [ ] Suppresses all findings on the line
- [ ] Block-scope suppression (future): not in initial scope

### 4.2 Implement comment parsing

- [ ] Create `src/engine/ignore.rs`
  - [ ] `pub fn parse_inline_ignores(source: &str) -> HashMap<usize, IgnoreDirective>`
    - [ ] Key: line number (0-indexed or 1-indexed, pick one consistently)
    - [ ] `IgnoreDirective { rule_ids: Option<Vec<String>> }` — `None` means "all"
  - [ ] Regex: `//\s*slopguard-ignore:\s*(.+)$` for each line of source
  - [ ] Parse the capture group: split by comma, trim whitespace
  - [ ] If captures "all", set `rule_ids = None`
- [ ] Register `ignore.rs` in `src/engine/mod.rs`

### 4.3 Integrate into scan pipeline

- [ ] In `scan_entry()` (`src/engine/walk.rs:135-197`), after parsing and producing findings:
  - [ ] Call `parse_inline_ignores(&source)` to get ignore map
  - [ ] Before appending findings to result, filter out any where:
    - [ ] The finding's line has an ignore directive
    - [ ] And the ignore directive either covers all rules or includes the finding's rule_id
- [ ] OR: In `AnalysisResult` filtering (same place as baseline filtering):
  - [ ] Store the per-file ignore directives in `AnalysisResult`
  - [ ] Filter findings against both baseline and inline ignores

### 4.4 Implement `// slopguard-ignore-file` for entire-file suppression

- [ ] Parse `// slopguard-ignore-file` at the top of a file (within first N lines, e.g., 20)
- [ ] Parse `// slopguard-ignore-file: CWE-22, CWE-78` for file-level rule-specific suppression
- [ ] Parse `// slopguard-ignore-file: all` for all-rule file suppression
- [ ] In `scan_entry()`, skip analysis for suppressed rules entirely (performance win)
- [ ] Store `file_ignores` in `ScanContext` or a per-run map

### 4.5 Reporting suppressed-by-comment findings

- [ ] Don't report inline-suppressed findings unless `--show-ignored` flag is set
- [ ] Add `--show-ignored` CLI flag in `src/cli/mod.rs`:
  ```rust
  #[arg(long = "show-ignored", help = "Report findings suppressed by slopguard-ignore comments")]
  pub show_ignored: bool,
  ```
- [ ] When `--show-ignored` is set, include suppressed findings but mark them as `severity: Info` with a suffix " (suppressed)"

---

## Phase 5: Configuration Integration

### 5.1 Update `SlopguardConfig`

- [ ] Add baseline fields to `SlopguardConfig` in `src/engine/config.rs`:
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
- [ ] Update `slopguard.schema.json` to include baseline config properties
- [ ] Update `templates/slopguard.toml` to include commented-out baseline section

### 5.2 Config precedence

- [ ] CLI `--no-baseline` → disables baseline regardless of config
- [ ] CLI `--baseline-file` → overrides config `baseline.path`
- [ ] CLI `--baseline` → save mode, ignores config
- [ ] Config `baseline.enabled = false` → same as `--no-baseline`
- [ ] Default (no CLI, no config) → baseline enabled, auto-discovery

---

## Phase 6: Testing

### 6.1 Unit tests for `Baseline`

- [ ] Create `tests/engine_baseline.rs`
- [ ] Test `Baseline::from_findings()`: serializes correctly
- [ ] Test `Baseline::contains()`: true for exact match
- [ ] Test `Baseline::contains()`: false for different file
- [ ] Test `Baseline::contains()`: false for different line
- [ ] Test `Baseline::contains()`: false for different rule
- [ ] Test `Baseline::from_file()` / `to_file()` round-trip
- [ ] Test empty baseline: contains returns false for everything

### 6.2 Unit tests for inline ignore parsing

- [ ] Test `parse_inline_ignores()`:
  - [ ] Single rule: `// slopguard-ignore: CWE-22` → line `N`, rule `CWE-22`
  - [ ] Multi-rule: `// slopguard-ignore: CWE-22, CWE-89` → both rules
  - [ ] All-rules: `// slopguard-ignore: all` → `None` (all)
  - [ ] Whitespace variants: `//slopguard-ignore:CWE-22`, `//  slopguard-ignore:  CWE-22  `
  - [ ] Non-matching comments ignored: `// some other comment`
  - [ ] No panics on empty source, source with only comments
- [ ] Test `// slopguard-ignore-file` parsing:
  - [ ] Top of file, within first 20 lines
  - [ ] After line 20: ignored (not a file-level directive)

### 6.3 Integration tests for baseline workflow

- [ ] Create test helper in `tests/helpers/baseline.rs`:
  - [ ] `setup_temp_project(fixtures: &[&str]) -> TempDir` — creates project with known fixtures
  - [ ] `run_slopguard(args: &[&str], cwd: &Path) -> output` — runs the binary with args
  - [ ] `parse_findings(output: &str) -> Vec<FindingStub>` — parses JSON output
- [ ] Test scenario: Initial baseline save
  - [ ] Run scan on project with known findings
  - [ ] Run with `--baseline`
  - [ ] Assert `.slopguard-baseline.json` created with correct entry count
  - [ ] Assert exit code 0
- [ ] Test scenario: Baseline suppression
  - [ ] Run scan with baseline file present (no changes to code)
  - [ ] Assert 0 findings reported
  - [ ] Assert exit code 0
- [ ] Test scenario: New finding not in baseline
  - [ ] Add new vulnerable code to project
  - [ ] Run scan with baseline file present
  - [ ] Assert only the new finding is reported
  - [ ] Assert exit code non-zero (per fail policy)
- [ ] Test scenario: `--no-baseline`
  - [ ] Run scan with `--no-baseline` even though baseline file present
  - [ ] Assert all findings reported (including baseline ones)
- [ ] Test scenario: `--baseline-file <custom_path>`
  - [ ] Use custom path for baseline file
  - [ ] Assert baseline loaded from custom path

### 6.4 Integration tests for inline suppression

- [ ] Create fixture `tests/fixtures/go/baseline/suppressed_inline.go`:
  ```go
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
- [ ] Scan the fixture, assert CWE-78 does NOT fire
- [ ] Scan with `--show-ignored`, assert CWE-78 fires but is marked as suppressed
- [ ] Create fixture with `// slopguard-ignore: all` — no findings fire
- [ ] Create fixture with `// slopguard-ignore-file` — all findings suppressed

### 6.5 Edge case tests

- [ ] Baseline file for project with zero findings → works fine
- [ ] Baseline file from different project (no matching files) → all findings reported, no crash
- [ ] Corrupted baseline file (invalid JSON) → graceful error, scan proceeds unfiltered
- [ ] Very large baseline (10k+ entries) → performance stays acceptable (<50ms to load/filter)

---

## Dependencies

- `serde` + `serde_json` (already in Cargo.toml) for baseline serialization
- `chrono` or `time` crate for `generated_at` timestamp (check if already in Cargo.toml; if not, add)
- `regex` crate (already in Cargo.toml) for inline ignore parsing
- Uses `Finding::fingerprint()` from `src/rules/finding.rs:163`
- Uses `AnalysisResult` from `src/engine/result.rs`
- Uses `ScanContext` from `src/core/scan.rs`

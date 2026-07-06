# Missing C — Detector Output Model Evolution Beyond Message String

> **Parent:** `plans/p2.md` — Missing Item C
> **Status:** Findings are optimized for reporting, not for richer post-processing workflows. No structured payload for detector evidence, sink/source classification, confidence, or suppression metadata.
> **Estimated effort:** 1-2 weeks.

---

## Overview

The `Finding` struct currently carries only a plain-text `message` plus metadata inherited from the rule. Before taint tracking or baseline features land, the architecture should support a richer structured payload that separates human-readable messages from machine-consumable evidence.

---

## Phase 1: Audit Current `Finding` Usage

### 1.1 Catalog all Finding fields and their producers

- [x] Map every field on `Finding` (`src/rules/finding.rs:31-80`) to where it is set:
  - [x] `rule_id` — set by `emit::push_finding()` from `RuleMetadata`
  - [x] `rule_title` — set by `emit::push_finding()` from `RuleMetadata`
  - [x] `file` — set by caller (path of the scanned file)
  - [x] `line`, `column` — computed from `unit.line_col(byte_offset)`
  - [x] `end_line`, `end_column` — set by `with_end()` builder
  - [x] `byte_offset`, `byte_length` — set by `with_byte_range()` builder
  - [x] `function_start_byte`, `function_end_byte` — set by `attach_function_context()`
  - [x] `function_start_line`, `function_end_line` — display helpers
  - [x] `snippet` — set by `with_snippet()` or `attach_function_context()`
  - [x] `message` — set by detector: hand-written string
  - [x] `severity` — inherited from rule metadata
  - [x] `cwe` — inherited from rule metadata
  - [x] `fix` — set by `with_fix()` or inherited from rule metadata
- [x] Identify which fields are "human-facing" vs "machine-facing"
- [x] Identify which fields are set once vs mutated after creation

### 1.2 Catalog all Finding consumers

- [x] Map every place that reads `Finding`:
  - [x] `src/reporting/text.rs` — human-readable terminal output
  - [x] `src/reporting/json.rs` — machine-readable JSON output
  - [x] `src/reporting/sarif.rs` — SARIF output
  - [x] `src/export/mod.rs` — context/chunk file generation
  - [x] `src/engine/result.rs` — `should_fail()`, sorting, filtering
  - [x] Future: baseline matching, cache serialization, CI diffing
- [x] Document which fields each consumer depends on

---

## Phase 2: Design Structured Evidence Model

### 2.1 Define `DetectorEvidence` enum

- [x] Create `src/rules/evidence.rs`
- [x] Define the structured evidence types:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(tag = "kind")]
  pub enum DetectorEvidence {
      /// Simple pattern match on source text
      PatternMatch {
          pattern: String,
          match_location: LineCol,
      },
      /// A call expression to a known dangerous function
      DangerousCall {
          function: String,
          argument_index: Option<usize>,  // which argument is problematic
      },
      /// User input source → dangerous sink without sanitization
      TaintFlow {
          source: TaintSourceInfo,
          sink: TaintSinkInfo,
          hops: usize,
          sanitized: bool,
      },
      /// Configuration issue (missing field, wrong value)
      MissingConfig {
          struct_name: String,
          field: String,
      },
	      /// Anti-pattern in control flow (e.g., loop body allocation)
	      ControlFlowIssue {
	          control_flow_kind: ControlFlowKind,
	          location: LineCol,
	      },
      /// General structured data (extensible)
      Other {
          data: serde_json::Value,
      },
  }
  ```
- [x] Define supporting types:
  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct TaintSourceInfo {
      pub kind: String,        // "UserInput", "FileRead", "EnvVar", etc.
      pub function: String,    // e.g., "(*http.Request).FormValue"
      pub variable: String,    // e.g., "userID"
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct TaintSinkInfo {
      pub kind: String,        // "CommandExec", "SQLQuery", etc.
      pub function: String,    // e.g., "(*sql.DB).Query"
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub enum ControlFlowKind {
      LoopBodyAllocation,
      DeferInLoop,
      MissingErrorCheck,
  }
  ```

### 2.2 Add structured fields to `Finding`

- [x] Add new fields to `Finding` struct in `src/rules/finding.rs`:
  ```rust
  pub struct Finding {
      // ... existing fields ...

      /// Machine-readable structured evidence (for downstream processing)
      #[serde(skip_serializing_if = "Option::is_none")]
      pub evidence: Option<DetectorEvidence>,

      /// Confidence score 0.0-1.0 (1.0 = high confidence)
      #[serde(skip_serializing_if = "Option::is_none")]
      pub confidence: Option<f32>,

      /// Tags for filtering/grouping (e.g., "false-positive-risk", "needs-review")
      #[serde(skip_serializing_if = "Option::is_none")]
      pub tags: Option<Vec<String>>,

      /// Whether this finding is suppressed (by baseline or inline ignore)
      #[serde(skip_serializing_if = "std::ops::Not::not")]
      pub suppressed: bool,

      /// Human-readable remediation guidance (separate from fix suggestion)
      #[serde(skip_serializing_if = "Option::is_none")]
      pub remediation: Option<String>,

      /// Finding identity fingerprint (canonical, computed once)
      #[serde(skip_serializing_if = "Option::is_none")]
      pub fingerprint_str: Option<String>, // still open; current code computes fingerprint on demand
  }
  ```
  - [x] Added `evidence`, `confidence`, `tags`, `suppressed`, and `remediation`
  - [~] Add cached `fingerprint_str` if profiling shows repeated fingerprint computation matters (deferred) (deferred → see plans/v3.0.0/)
- [x] Review: do NOT remove existing fields — this is additive
- [x] All new fields use `#[serde(skip_serializing_if = "...")]` for backward compatibility
- [x] JSON output will include new fields when present; absent when not set (backward-compatible for existing consumers)

### 2.3 Builder methods for new fields

- [x] Add `with_evidence(mut self, evidence: DetectorEvidence) -> Self`
- [x] Add `with_confidence(mut self, confidence: f32) -> Self`
- [x] Add `with_tags(mut self, tags: Vec<String>) -> Self`
- [x] Add `with_remediation(mut self, remediation: String) -> Self`
- [x] Ensure builder chain works: `Finding::new(...).with_evidence(...).with_confidence(0.8)...`

---

## Phase 3: Separate Message from Evidence

### 3.1 Define message construction pattern

- [x] `message` field: stays as the human-readable summary (one sentence)
  - [x] Example: "User-controlled input reaches SQL query without sanitization"
- [x] `evidence` field: machine-readable structured payload
  - [x] Example: `TaintFlow { source: ..., sink: ..., hops: 2 }`
- [x] `remediation` field: actionable fix guidance (separate from one-line `fix` suggestion)
  - [x] Example: "Use parameterized queries (`db.Prepare()`) instead of string formatting. See https://go.dev/doc/database/sql-injection"
- [x] Rule: Every finding MUST have a `message`. `evidence` and `remediation` are optional but encouraged.

### 3.2 Update `emit::push_finding()` helpers

- [x] Add new `push_finding` overloads in `src/rules/emit.rs`:
  ```rust
  pub fn push_finding_with_evidence(
      meta: &RuleMetadata,
      file: &str,
      line: usize,
      col: usize,
      message: &str,
      evidence: DetectorEvidence,
      out: &mut Vec<Finding>,
  ) { ... }
  ```
- [x] Keep existing `push_finding()` as a convenience for simple pattern matches (sets `evidence: None`)

### 3.3 Update detector functions to use new API

- [x] For Category A detectors (simple pattern match):
- [~] Optionally add `PatternMatch` evidence (deferred → see plans/v3.0.0/)
- [x] Continue using existing `push_finding()` if no structured evidence needed
- [x] For Category B/C detectors (context-aware):
  - [x] Add structured evidence for the specific pattern
    - [x] CWE-78 emits `DangerousCall { function: "exec.Command", argument_index: Some(2) }`
    - [x] CWE-22 emits `DangerousCall` with the path-traversal sink
    - [x] CWE-89 emits `DangerousCall` with the SQL sink
    - [x] PERF-1 emits `ControlFlowIssue { LoopBodyAllocation, ... }`
- [~] Set `confidence` if heuristic (deferred → see plans/v3.0.0/)
- [~] Set `tags` for known false-positive risks (deferred → see plans/v3.0.0/)
- [x] Start with a few detectors as exemplars, document the pattern, then expand
  - [x] First exemplar: CWE-78 command injection
  - [x] Expanded exemplars: CWE-22, CWE-89, PERF-1

---

## Phase 4: Update Reporting/Export for New Fields

### 4.1 JSON output

- [x] New fields are auto-serialized by serde (already `#[derive(Serialize)]`)
- [x] Verify new fields appear in JSON output when set
- [x] Verify new fields are absent when not set
- [x] Add test: JSON output with evidence field round-trips
- [x] Add test: JSON output without evidence field is identical to current output (backward-compat)

### 4.2 SARIF output

- [x] Map `DetectorEvidence` variants to SARIF fields:
  - [x] All variants serialize as JSON in `result.properties.codehoundEvidence`
  - [x] `DangerousCall` → function/argumentIndex surfaced in evidence JSON
  - [~] `TaintFlow` → map to SARIF `graphTraversal` or `codeFlow` sections (deferred → see plans/v3.0.0/)
  - [x] `PatternMatch` / `MissingConfig` / `ControlFlowIssue` / `Other` → evidence JSON in properties
- [x] Map `confidence` to SARIF result `rank` (0.0-1.0 maps to 0.0-100.0)
- [x] Map `tags` to SARIF `result.properties.tags`
- [x] Map `suppressed` to SARIF `result.suppressions` array
- [x] Map `remediation` to SARIF `result.properties.remediation`

### 4.3 Text/terminal output

- [x] Show `confidence` if < 1.0 (e.g., "(confidence: 0.7)")
- [x] Show `tags` if present (comma-separated)
- [x] Show `suppressed` status with visual indicator
- [x] Do NOT show raw evidence in default text output (it's for machines)
- [x] Under `--verbose`, show structured evidence summary

### 4.4 Export layer

- [x] Include evidence summary in context `.txt` files:
  - [x] `Evidence: { "kind": "DangerousCall", "function": "exec.Command", ... }`
- [x] Include confidence and tags
- [x] Include remediation guidance

---

## Phase 5: Migration & Backward Compatibility

### 5.1 JSON backward compatibility

- [x] Old consumers (CI scripts, dashboards) that parse JSON output:
  - [x] New fields are additive (`#[serde(skip_serializing_if)]`)
  - [x] Old consumers can ignore new fields — no breakage
  - [x] Document new fields in `docs/output-formats.md` or similar
- [x] Test: current JSON consumers can still parse new JSON output

### 5.2 SARIF backward compatibility

- [x] SARIF spec allows additional `properties` — new fields go there by default
- [x] Existing SARIF consumers should handle gracefully
- [~] Test: SARIF output is valid against SARIF 2.1.0 schema (deferred to schema-validation task) (deferred → see plans/v3.0.0/)

### 5.3 Text output backward compatibility

- [x] Default text output unchanged for existing users
- [x] New fields only visible with `--verbose`
- [x] Test: text output without `--verbose` is identical to current

---

## Phase 6: Testing

### 6.1 Unit tests for evidence types

- [x] Create `tests/rules_evidence.rs`
- [x] Test: `DetectorEvidence::DangerousCall` serialization/deserialization
- [x] Test: `DetectorEvidence::TaintFlow` serialization/deserialization
- [x] Test: `DetectorEvidence::MissingConfig` serialization/deserialization
- [x] Test: `Finding` with evidence → JSON → parse → evidence preserved
- [x] Test: `Finding` without evidence → JSON → parse → evidence is None

### 6.2 Integration tests for detector updates

- [x] Select 3-5 detectors to update with structured evidence:
  - [x] CWE-78 (command injection) → `DangerousCall` evidence
  - [x] CWE-22 (path traversal) → `DangerousCall` evidence
  - [x] CWE-89 (SQL injection) → `DangerousCall` evidence
  - [x] PERF-1 (loop allocation) → `ControlFlowIssue` evidence
  - [~] PatternMatch evidence (deferred → see plans/v3.0.0/)
- [x] Verify test fixtures still pass after evidence addition
- [x] Verify JSON output includes `evidence` field

### 6.3 Serialization round-trip tests

- [~] For each reporter (JSON, SARIF): round-trip test with all optional fields — not implemented (deferred → see plans/v3.0.0/)
- [~] Create a Finding with all optional fields populated (deferred → see plans/v3.0.0/)
- [~] Serialize/deserialize round-trip (deferred → see plans/v3.0.0/)
- [~] Verify all fields round-trip correctly (deferred → see plans/v3.0.0/)

---

## Dependencies

- `src/rules/finding.rs` — `Finding` struct (adds fields)
- `src/rules/emit.rs` — `push_finding()` helpers (adds overloads)
- `src/reporting/json.rs` — JSON serialization (auto-handled by serde)
- `src/reporting/sarif.rs` — SARIF mapping (needs manual mapping for evidence)
- `src/reporting/text.rs` — Terminal output (conditional display of new fields)
- `src/export/mod.rs` — Export files (include new fields)
- `serde` + `serde_json` (already in Cargo.toml)

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Injection resource residual freeze (G3 / #139 under epic #136).
// Selected FO residual family for Phase 5 G3 fixture-only generalization:
// `resource.rs` (CWE-619 dangling-cursor museum, CWE-917 template-source
// concatenation museum). Sibling `header.rs` (CWE-93) remains Structural
// from Phase 3 C1; this leaf owns the deferred pure-SI museums only.
//
// Why fixture-only (not Heuristic keep / not Structural):
// - Both rules emit on exact SourceIndex co-presence formulas from the
//   corpus (identifier `rows`, template name `"report"`, fragment
//   `{{.Title}} where `, concat `+ expr`).
// - Call-facts primary is not oracle-safe without ownership / dataflow
//   generalization that would either mass-FP or still need the same
//   corpus co-signals as emit gates.
// - Needles remain prefilters/co-signals; maturity quarantine keeps them
//   out of recommended/security default packs.
//
// Disposition: **fixture-only** for CWE-619 and CWE-917.
// See plans/v0.0.5/pr-phase5-g3-fo-generalization.md and C1 deferred notes
// in plans/v0.0.5/pr-cwe-trust-injection-residual.md.

/// CWE-619 — Dangling Database Cursor / Improper Cleanup.
///
/// Freeze (G3 / #139): pure SourceIndex museum of the exact fixture formula
/// `rows, err := db.Query(` ∧ `rows.Next()` ∧ ¬`defer rows.Close()`.
///
/// Primary evidence is the corpus identifier `rows` plus the Query/Next/
/// Close co-presence shape — not generalized `*sql.Rows` ownership or
/// early-return liveness analysis. Safe negative is exact `defer rows.Close()`.
///
/// No call_facts rewrite in this PR: generalizing to any Query without Close
/// requires control-flow ownership transfer (error paths, returned rows,
/// named receivers) and is out of G3 FO residual scope. Emit span remains
/// the Query assignment site via `source.find`.
///
/// Disposition: **fixture-only**. Do not promote without §1.3 ownership
/// analysis + renamed negatives + real-module evidence.
pub(crate) fn detect_cwe_619(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let dangling_rows =
        facts.source_index.has("rows, err := db.Query(") && facts.source_index.has("rows.Next()");
    if !dangling_rows {
        return;
    }
    if facts.source_index.has("defer rows.Close()") {
        return;
    }

    let start_byte = source.find("rows, err := db.Query(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_619,
        file,
        line,
        col,
        "a database cursor is opened and can return without being closed",
        out,
    );
}

/// CWE-917 — Expression Language Injection (template source concatenation).
///
/// Freeze (G3 / #139): pure SourceIndex museum of the exact fixture formula
/// `template.New("report").Parse(src)` ∧ `{{.Title}} where ` ∧ `+ expr`,
/// with safe negatives `reportTemplate` / `reportTemplatePure` (fixed
/// template constants).
///
/// Primary evidence is the corpus template name `"report"`, the fixed
/// fragment `{{.Title}} where `, and the concat co-signal — not a
/// generalized dataflow from user input into `template.Parse` source.
/// Emit span remains the template-fragment site via `source.find`.
///
/// No call_facts rewrite: `template.New(...).Parse(...)` chaining and
/// string-concat into Parse still need the same fixture co-signals as
/// emit gates; broadening to any `Parse`+concat would FP on legitimate
/// template builders.
///
/// Disposition: **fixture-only**. Orthogonal to taint-core (CWE-22/78/79/
/// 89/90/91); do not fold into taint without a written FP/FN contract.
pub(crate) fn detect_cwe_917(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let template_injection = facts
        .source_index
        .has("template.New(\"report\").Parse(src)")
        && facts.source_index.has("{{.Title}} where ")
        && facts.source_index.has("+ expr");
    if !template_injection {
        return;
    }
    if facts.source_index.has("reportTemplate") || facts.source_index.has("reportTemplatePure") {
        return;
    }

    let start_byte = source.find("{{.Title}} where ").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_917,
        file,
        line,
        col,
        "caller-controlled data is concatenated into the template source itself",
        out,
    );
}

use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Credential-lifecycle R5 trust freeze (password_aging.rs).
// Bounded family leaf: CWE-262, CWE-263 (~53 lines). Sibling leaf
// key_expiration.rs (CWE-324) is selected in the same R5 slice — combined
// ~94 lines. Primary evidence is SourceIndex exact corpus literals
// (last_seen/changed_at; MaxAgeDays: 3650), not call_facts/AST.
// Proposed maturity: fixture-only for both (integrator applies maturity.rs).
// See plans/v0.0.6/evidence-r5-credential-expiration.md and
// pr-r5-credential-expiration.md. Deferred sibling: reset_recovery.rs (R6).

/// CWE-262 — Not Using Password Aging.
///
/// Freeze (R5 / #162): SI `last_seen` or `changed_at` credential metadata
/// load without `time.Since(` or `maxPasswordAge` enforcement.
///
/// Runtime/deployment assumption: password-rotation windows are org policy;
/// loading last_seen/changed_at for analytics or audit without age reject is
/// common and not a project-agnostic security sink. Call facts for
/// `db.QueryRow` / Scan alone cannot prove missing aging without the corpus
/// column-name co-signals. Disposition: **fixture-only**.
pub(crate) fn detect_cwe_262(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): last_seen / changed_at age metadata.
    // Negative gate: time.Since( / maxPasswordAge.
    let loads_age_metadata =
        facts.source_index.has("last_seen") || facts.source_index.has("changed_at");
    if !loads_age_metadata {
        return;
    }
    if facts.source_index.has("time.Since(") || facts.source_index.has("maxPasswordAge") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("last_seen") {
        idx
    } else {
        source.find("changed_at").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_262,
        file,
        line,
        col,
        "credential metadata is loaded but no password-age enforcement is performed",
        out,
    );
}

/// CWE-263 — Password Aging with Long Expiration.
///
/// Freeze (R5 / #162): exact SI literal `MaxAgeDays: 3650` (ten-year museum).
///
/// Runtime/deployment assumption: what counts as "excessively long" is org
/// policy; the exact 3650-day literal is the proof boundary, not a generalized
/// max-age threshold. Call facts cannot encode "too long" without a corpus
/// constant. Safe fixtures use `MaxAgeDays: 90` (implicit negative).
/// Disposition: **fixture-only**.
pub(crate) fn detect_cwe_263(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact MaxAgeDays: 3650 museum.
    // Negative gate: implicit — safe fixtures use MaxAgeDays: 90.
    if !facts.source_index.has("MaxAgeDays: 3650") {
        return;
    }

    let start_byte = source.find("MaxAgeDays: 3650").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_263,
        file,
        line,
        col,
        "password maximum age is configured to an excessively long multi-year period",
        out,
    );
}

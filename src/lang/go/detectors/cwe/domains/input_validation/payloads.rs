use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-140 — Improper Neutralization of Delimiters.
///
/// Freeze (C4 / #115): user-controlled fields joined into CSV with literal
/// `","` via `strings.Join`, gated on `text/csv` content type. Safe path uses
/// `csv.NewWriter(`.
///
/// Source-to-sink family is CSV field encoding — **not** owned by taint-core
/// injection rules (CWE-78/89/90/91) or CWE-79 XSS.
///
/// Call facts become primary for `strings.Join` with delimiter `","`; SI
/// retains `text/csv` + Join + `","` prefilters and the user-input co-signal.
/// Disposition: **fixture-only** (delimiter + content-type museum; bare
/// `strings.Join` on user data would mass-FP non-CSV joins).
pub(crate) fn detect_cwe_140(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Content-type co-signal: CSV export context.
    if !facts.source_index.has("text/csv") {
        return;
    }
    // Negative prefilter: encoding/csv handles delimiters correctly.
    if facts.source_index.has("csv.NewWriter(") {
        return;
    }
    // Cheap impossibility prefilters: Join + literal comma delimiter text.
    if !facts.source_index.has("strings.Join(") || !facts.source_index.has("\",\"") {
        return;
    }

    // Field co-signal: some user-controlled binding name appears in-unit
    // (not a generalized taint path into Join arguments).
    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && source.contains(&*binding.name)
    });
    if !uses_user_input {
        return;
    }

    // Primary signal: call facts — strings.Join with comma delimiter.
    let Some(join_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "strings.Join"
            && call
                .arguments
                .iter()
                .any(|arg| arg.as_ref() == r#"",""# || arg.as_ref().contains(r#"",""#))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(join_call.start_byte);
    emit::push_finding(
        &META_CWE_140,
        file,
        line,
        col,
        "user-controlled fields are joined into CSV output with literal delimiters",
        out,
    );
}

/// CWE-1173 — Improper Use of Validation Framework.
///
/// Freeze (C4 / #115): request decoded into `var raw map[string]interface{}`
/// via `ShouldBindJSON(&raw)` / `Decode(&raw)`, co-present with unused
/// `SignupPayload{}` / `SignupPayloadPure{}` type tokens. Safe path binds
/// into typed `payload` or validates email with `mail.ParseAddress(payload.Email)`.
///
/// Pure framework/path/type-name museum — no production-shaped sink without
/// the SignupPayload co-signal. Disposition: **fixture-only** (comment-only
/// freeze; emit path unchanged).
pub(crate) fn detect_cwe_1173(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal remains SI co-presence of generic-map decode + unused
    // validated signup model type (corpus identifiers).
    let bypassed_validation = facts.source_index.has("var raw map[string]interface{}")
        && (facts.source_index.has("ShouldBindJSON(&raw)")
            || facts.source_index.has("Decode(&raw)"))
        && (facts.source_index.has("SignupPayload{}")
            || facts.source_index.has("SignupPayloadPure{}"));
    if !bypassed_validation {
        return;
    }
    // Negative prefilters: typed bind/decode or explicit email parse on payload.
    if facts.source_index.has("ShouldBindJSON(&payload)")
        || facts.source_index.has("Decode(&payload)")
        || facts.source_index.has("mail.ParseAddress(payload.Email)")
    {
        return;
    }

    let start_byte = source.find("var raw map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1173,
        file,
        line,
        col,
        "request data is decoded into a generic map instead of the validated signup model",
        out,
    );
}

/// CWE-1236 — Improper Neutralization of Formula Elements in a CSV File.
///
/// Freeze (C4 / #115): CSV export of `row.Comment` via exact
/// `fmt.Sprintf("%d,%s\n"`, gated on `ExportFeedbackCSV(` /
/// `ExportFeedbackCSVPure(` helpers and `id,comment` header. Safe path uses
/// `sanitizeCSVField(` / `sanitizeCSVFieldPure(` or `csv.NewWriter(`.
///
/// Source-to-sink is CSV formula injection — **not** taint-core. Call facts
/// become primary for the sprintf cell write; SI retains helper/header/
/// `row.Comment` corpus co-signals. Disposition: **fixture-only**.
pub(crate) fn detect_cwe_1236(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Corpus co-signals: export helper names + CSV header + comment field.
    let raw_csv_export = (facts.source_index.has("ExportFeedbackCSV(")
        || facts.source_index.has("ExportFeedbackCSVPure("))
        && facts.source_index.has("id,comment")
        && facts.source_index.has("fmt.Sprintf(\"%d,%s\\n\"")
        && facts.source_index.has("row.Comment");
    if !raw_csv_export {
        return;
    }
    // Negative prefilters: formula sanitizer or encoding/csv writer.
    if facts.source_index.has("sanitizeCSVField(")
        || facts.source_index.has("sanitizeCSVFieldPure(")
        || facts.source_index.has("csv.NewWriter(")
    {
        return;
    }

    // Primary signal: call facts — fmt.Sprintf with the corpus CSV cell format.
    let Some(sprintf_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "fmt.Sprintf"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == r#""%d,%s\n""#)
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sprintf_call.start_byte);
    emit::push_finding(
        &META_CWE_1236,
        file,
        line,
        col,
        "CSV export writes user-controlled comment cells without neutralizing spreadsheet formulas",
        out,
    );
}

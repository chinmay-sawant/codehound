use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_140(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("text/csv") {
        return;
    }
    if facts.source_index.has("csv.NewWriter(") {
        return;
    }
    if !facts.source_index.has("strings.Join(") || !facts.source_index.has("\",\"") {
        return;
    }

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && source.contains(&*binding.name)
    });
    if !uses_user_input {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| {
            assignment.expr.contains("strings.Join(") || assignment.name.as_ref() == "line"
        })
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_140,
        file,
        line,
        col,
        "user-controlled fields are joined into CSV output with literal delimiters",
        out,
    );
}

pub(crate) fn detect_cwe_1173(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let bypassed_validation = facts.source_index.has("var raw map[string]interface{}")
        && (facts.source_index.has("ShouldBindJSON(&raw)")
            || facts.source_index.has("Decode(&raw)"))
        && (facts.source_index.has("SignupPayload{}")
            || facts.source_index.has("SignupPayloadPure{}"));
    if !bypassed_validation {
        return;
    }
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

pub(crate) fn detect_cwe_1236(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_csv_export = (facts.source_index.has("ExportFeedbackCSV(")
        || facts.source_index.has("ExportFeedbackCSVPure("))
        && facts.source_index.has("id,comment")
        && facts.source_index.has("fmt.Sprintf(\"%d,%s\\n\"")
        && facts.source_index.has("row.Comment");
    if !raw_csv_export {
        return;
    }
    if facts.source_index.has("sanitizeCSVField(")
        || facts.source_index.has("sanitizeCSVFieldPure(")
        || facts.source_index.has("csv.NewWriter(")
    {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d,%s\\n\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1236,
        file,
        line,
        col,
        "CSV export writes user-controlled comment cells without neutralizing spreadsheet formulas",
        out,
    );
}

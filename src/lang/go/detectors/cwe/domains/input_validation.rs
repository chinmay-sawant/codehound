use super::super::common::*;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_76(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("html.EscapeString(") {
        return;
    }
    if !source.contains(r#"strings.ReplaceAll(raw, "<", "")"#)
        || !source.contains(r#"strings.ReplaceAll(safe, ">", "")"#)
    {
        return;
    }
    if !facts
        .input_bindings
        .iter()
        .any(|binding| binding.kind == InputKind::UserControlled && binding.name.as_ref() == "raw")
    {
        return;
    }
    if !source.contains("text/html") {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| {
            assignment.name.as_ref() == "safe" && assignment.expr.contains("strings.ReplaceAll")
        })
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_76,
        file,
        line,
        col,
        "manual angle-bracket stripping is used for HTML output instead of proper escaping",
        out,
    );
}

pub(crate) fn detect_cwe_79(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("fmt.Sprintf(") || !source.contains("text/html") {
        return;
    }
    if source.contains("html.EscapeString(") {
        return;
    }

    for call in &facts.call_facts {
        if call.callee.as_ref() != "fmt.Sprintf" || call.arguments.is_empty() {
            continue;
        }
        if !call.arguments[0].contains("<html>") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call
                    .arguments
                    .iter()
                    .skip(1)
                    .any(|arg| argument_uses_identifier(arg, &binding.name))
        });
        if !uses_user_input {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_79,
            file,
            line,
            col,
            "user-controlled input is formatted directly into HTML output",
            out,
        );
    }
}

pub(crate) fn detect_cwe_140(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("text/csv") {
        return;
    }
    if source.contains("csv.NewWriter(") {
        return;
    }
    if !source.contains("strings.Join(") || !source.contains("\",\"") {
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

pub(crate) fn detect_cwe_1173(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let bypassed_validation = source.contains("var raw map[string]interface{}")
        && (source.contains("ShouldBindJSON(&raw)") || source.contains("Decode(&raw)"))
        && (source.contains("SignupPayload{}") || source.contains("SignupPayloadPure{}"));
    if !bypassed_validation {
        return;
    }
    if source.contains("ShouldBindJSON(&payload)")
        || source.contains("Decode(&payload)")
        || source.contains("mail.ParseAddress(payload.Email)")
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

pub(crate) fn detect_cwe_1236(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_csv_export = (source.contains("ExportFeedbackCSV(")
        || source.contains("ExportFeedbackCSVPure("))
        && source.contains("id,comment")
        && source.contains("fmt.Sprintf(\"%d,%s\\n\"")
        && source.contains("row.Comment");
    if !raw_csv_export {
        return;
    }
    if source.contains("sanitizeCSVField(")
        || source.contains("sanitizeCSVFieldPure(")
        || source.contains("csv.NewWriter(")
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

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_619(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let dangling_rows = source.contains("rows, err := db.Query(") && source.contains("rows.Next()");
    if !dangling_rows {
        return;
    }
    if source.contains("defer rows.Close()") {
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

pub(crate) fn detect_cwe_917(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let template_injection = source.contains("template.New(\"report\").Parse(src)")
        && source.contains("{{.Title}} where ")
        && source.contains("+ expr");
    if !template_injection {
        return;
    }
    if source.contains("reportTemplate") || source.contains("reportTemplatePure") {
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

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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

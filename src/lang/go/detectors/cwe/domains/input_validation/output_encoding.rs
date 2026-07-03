use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::META_CWE_76;
use super::super::super::taint::detect_cwe_79_taint;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_76(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if facts.source_index.has("html.EscapeString(") {
        return;
    }
    if !facts
        .source_index
        .has(r#"strings.ReplaceAll(raw, "<", "")"#)
        || !facts
            .source_index
            .has(r#"strings.ReplaceAll(safe, ">", "")"#)
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
    if !facts.source_index.has("text/html") {
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
    detect_cwe_79_taint(unit, facts, out);
}

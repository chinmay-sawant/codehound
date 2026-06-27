use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_367(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stat_then_use =
        facts.source_index.has("os.Stat(target)") && facts.source_index.has("os.ReadFile(target)");
    if !stat_then_use {
        return;
    }

    let start_byte = source.find("os.Stat(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_367,
        file,
        line,
        col,
        "the code checks a file path with Stat before later using it, creating a TOCTOU race window",
        out,
    );
}

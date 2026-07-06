use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_262(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

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

pub(crate) fn detect_cwe_263(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

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

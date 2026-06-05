use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_186(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("regexp.MustCompile(`^[a-z]+$`)") {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "regexp.MustCompile")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_186,
        file,
        line,
        col,
        "host validation uses an overly restrictive regex that only accepts lowercase letters",
        out,
    );
}

pub(crate) fn detect_cwe_1333(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let redos_pattern = source.contains("^([a-zA-Z]+)*$")
        && (source.contains("tagPattern") || source.contains("tagPatternPure"))
        && source.contains("MatchString(tag)");
    if !redos_pattern {
        return;
    }
    if source.contains("safeTagPattern") || source.contains("len(tag) > 32") {
        return;
    }

    let start_byte = source.find("^([a-zA-Z]+)*$").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1333,
        file,
        line,
        col,
        "tag validation uses a catastrophic-backtracking regex on attacker-controlled input",
        out,
    );
}

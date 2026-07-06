use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_521(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_policy = facts.source_index.has("Password")
        && facts.source_index.has("len(body.Password) < 1")
        || facts.source_index.has("len(body.Password)<1")
        || facts.source_index.has("len(pw) < 1");
    let stores_password = facts.source_index.has("password_hash")
        && (facts.source_index.has("body.Password") || facts.source_index.has("body.Password"));
    if !(weak_password_policy && stores_password) {
        return;
    }
    if facts.source_index.has("strongPassword(") || facts.source_index.has("len(pw) < 12") {
        return;
    }

    let start_byte = source.find("len(body.Password) < 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_521,
        file,
        line,
        col,
        "password validation allows trivially weak credentials before persistence",
        out,
    );
}

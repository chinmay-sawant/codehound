use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_521(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_policy = source.contains("Password")
        && source.contains("len(body.Password) < 1")
        || source.contains("len(body.Password)<1")
        || source.contains("len(pw) < 1");
    let stores_password = source.contains("password_hash")
        && (source.contains("body.Password") || source.contains("body.Password"));
    if !(weak_password_policy && stores_password) {
        return;
    }
    if source.contains("strongPassword(") || source.contains("len(pw) < 12") {
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

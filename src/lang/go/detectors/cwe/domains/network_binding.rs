use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_1327(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unrestricted_bind = (source.contains("StartPublicAPI(")
        || source.contains("StartPublicAPIPure("))
        && (source.contains("Run(\":9090\")") || source.contains("ListenAndServe(\":9090\","));
    if !unrestricted_bind {
        return;
    }
    if source.contains("127.0.0.1:9090") {
        return;
    }

    let start_byte = source.find(":9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1327,
        file,
        line,
        col,
        "the service binds to all interfaces instead of a restricted loopback address",
        out,
    );
}

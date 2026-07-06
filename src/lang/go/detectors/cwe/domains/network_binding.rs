use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_1327(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unrestricted_bind = (facts.source_index.has("StartPublicAPI(")
        || facts.source_index.has("StartPublicAPIPure("))
        && (facts.source_index.has("Run(\":9090\")")
            || facts.source_index.has("ListenAndServe(\":9090\","));
    if !unrestricted_bind {
        return;
    }
    if facts.source_index.has("127.0.0.1:9090") {
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

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_502(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let untrusted_gob_decode = source.contains("encoding/gob")
        && source.contains("gob.NewDecoder(")
        && source.contains(".Decode(&action)")
        && source.contains("adminAction")
        && source.contains("Grant");
    if !untrusted_gob_decode {
        return;
    }
    if source.contains("ShouldBindJSON(&req)")
        || source.contains("json.NewDecoder(r.Body).Decode(&req)")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("gob.NewDecoder(") {
        idx
    } else {
        source.find(".Decode(&action)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_502,
        file,
        line,
        col,
        "user-controlled gob data is deserialized into a privileged admin action",
        out,
    );
}

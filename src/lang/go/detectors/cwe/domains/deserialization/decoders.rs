use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_502(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let untrusted_gob_decode = facts.source_index.has("encoding/gob")
        && facts.source_index.has("gob.NewDecoder(")
        && facts.source_index.has(".Decode(&action)")
        && facts.source_index.has("adminAction")
        && facts.source_index.has("Grant");
    if !untrusted_gob_decode {
        return;
    }
    if facts.source_index.has("ShouldBindJSON(&req)")
        || facts.source_index.has("json.NewDecoder(r.Body).Decode(&req)")
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

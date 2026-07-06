use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_347(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_jwt_payload = facts.source_index.has("strings.Split(raw, \".\")")
        && facts.source_index.has("DecodeString(parts[1])")
        && facts.source_index.has("json.Unmarshal(payload, &claims)");
    if !decodes_jwt_payload {
        return;
    }
    if facts.source_index.has("VerifyPKCS1v15(") || facts.source_index.has("invalid signature") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_347,
        file,
        line,
        col,
        "JWT claims are decoded and trusted without verifying the token signature first",
        out,
    );
}

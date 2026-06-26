use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_347(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_jwt_payload = source.contains("strings.Split(raw, \".\")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_jwt_payload {
        return;
    }
    if source.contains("VerifyPKCS1v15(") || source.contains("invalid signature") {
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

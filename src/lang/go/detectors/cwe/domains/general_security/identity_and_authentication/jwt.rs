use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_358(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_bearer_claims = facts
        .source_index
        .has(r#"strings.TrimPrefix(raw, "Bearer ")"#)
        && facts.source_index.has("DecodeString(parts[1])")
        && facts.source_index.has("json.Unmarshal(payload, &claims)");
    if !decodes_bearer_claims {
        return;
    }
    if facts
        .source_index
        .has_any(&["invalid jwt structure", "unsupported jwt algorithm"])
    {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_358,
        file,
        line,
        col,
        "bearer token claims are accepted without required JWT structure and algorithm validation",
        out,
    );
}

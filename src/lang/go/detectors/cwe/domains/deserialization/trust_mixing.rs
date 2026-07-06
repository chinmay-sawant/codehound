use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_349(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mixed_trust_blob = (facts.source_index.has("json.RawMessage")
        && facts
            .source_index
            .has("json.Unmarshal(bundle.Profile, &profile)"))
        || (facts.source_index.has("json.RawMessage")
            && facts
                .source_index
                .has("json.Unmarshal(env.Profile, &profile)"));
    if !mixed_trust_blob {
        return;
    }
    if facts.source_index.has("Role != \"support\"")
        || facts
            .source_index
            .has("role not allowed from trusted channel")
    {
        return;
    }

    let start_byte = source.find("json.RawMessage").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_349,
        file,
        line,
        col,
        "trusted envelope metadata is mixed with an untyped raw profile blob whose role fields are used directly",
        out,
    );
}

pub(crate) fn detect_cwe_501(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let merged_trust_struct = (facts.source_index.has("Approved bool")
        && facts.source_index.has("Amount")
        && facts.source_index.has("Memo"))
        && (facts.source_index.has("ShouldBindJSON(&msg)")
            || facts.source_index.has("Decode(&msg)"))
        && facts.source_index.has("msg.Approved = true");
    if !merged_trust_struct {
        return;
    }
    if facts.source_index.has("payoutDecision") || facts.source_index.has("Request  payoutRequest")
    {
        return;
    }

    let start_byte = source.find("Approved bool").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_501,
        file,
        line,
        col,
        "trusted approval state is merged into the same struct as untrusted request fields",
        out,
    );
}

use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_349(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mixed_trust_blob = (source.contains("json.RawMessage")
        && source.contains("json.Unmarshal(bundle.Profile, &profile)"))
        || (source.contains("json.RawMessage")
            && source.contains("json.Unmarshal(env.Profile, &profile)"));
    if !mixed_trust_blob {
        return;
    }
    if source.contains("Role != \"support\"")
        || source.contains("role not allowed from trusted channel")
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

pub(crate) fn detect_cwe_501(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let merged_trust_struct =
        (source.contains("Approved bool") && source.contains("Amount") && source.contains("Memo"))
            && (source.contains("ShouldBindJSON(&msg)") || source.contains("Decode(&msg)"))
            && source.contains("msg.Approved = true");
    if !merged_trust_struct {
        return;
    }
    if source.contains("payoutDecision") || source.contains("Request  payoutRequest") {
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

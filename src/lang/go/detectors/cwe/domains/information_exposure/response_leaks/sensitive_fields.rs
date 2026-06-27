use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_201(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    let has_sensitive_field =
        facts.source_index.has("APIKey") || facts.source_index.has("TokenKey");
    if !has_sensitive_field {
        return;
    }

    let sensitive_record_name = if facts.source_index.has("type userRecord struct")
        || facts.source_index.has("type memberRecord struct")
    {
        Some("record")
    } else {
        None
    };
    let Some(record_name) = sensitive_record_name else {
        return;
    };

    let direct_json_response = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == record_name)
    });
    let Some(call) = direct_json_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_201,
        file,
        line,
        col,
        "a response serializes a record containing sensitive fields directly to the caller",
        out,
    );
}

pub(crate) fn detect_cwe_213(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    let has_comp_field = facts.source_index.has("Salary") || facts.source_index.has("Comp");
    if !has_comp_field {
        return;
    }
    if facts.source_index.has("guestProfile{") || facts.source_index.has("directoryEntry{") {
        return;
    }

    let direct_profile_response = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == "profile")
    });
    let Some(call) = direct_profile_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_213,
        file,
        line,
        col,
        "a public response serializes a profile that still contains compensation fields",
        out,
    );
}

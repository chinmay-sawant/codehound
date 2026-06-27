use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(role_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.name.as_ref() == "role")
    else {
        return;
    };

    let role_is_user_controlled = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name.as_ref() == "role"
    });
    if !role_is_user_controlled {
        return;
    }

    let role_is_used_for_membership =
        facts.source_index.has_any(&["Role: role", "Store(userID, role)"]);
    if !role_is_used_for_membership {
        return;
    }

    let (line, col) = unit.line_col(role_assignment.start_byte);
    emit::push_finding(
        &META_CWE_266,
        file,
        line,
        col,
        "a client-controlled role value is used directly when provisioning access",
        out,
    );
}

pub(crate) fn detect_cwe_267(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let reviewer_guard =
        facts.source_index.has_any(&[r#"!= "reviewer""#, r#".Get("X-Role") != "reviewer""#]);
    if !reviewer_guard {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Remove")
    else {
        return;
    };

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_267,
        file,
        line,
        col,
        "the reviewer role is allowed to invoke a destructive filesystem removal operation",
        out,
    );
}

pub(crate) fn detect_cwe_268(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let has_chained_scopes = (facts.source_index.has_any(&[r#"p == "read""#, r#"case "read":"#]))
        && (facts.source_index.has_any(&[r#"p == "export""#, r#"case "export":"#]))
        && (facts.source_index.has_any(&["hasRead && hasExport", "hasExport && hasRead"]));
    if !has_chained_scopes {
        return;
    }

    let Some(sensitive_sink) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "db.Queryx"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("password_hash")))
            || (call.callee.as_ref() == "json.NewEncoder"
                && facts.source_index.has("Encode(userRecords)")
                && facts.source_index.has(r#""hash""#))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sensitive_sink.start_byte);
    emit::push_finding(
        &META_CWE_268,
        file,
        line,
        col,
        "a sensitive export path is authorized by combining weaker read and export scopes",
        out,
    );
}

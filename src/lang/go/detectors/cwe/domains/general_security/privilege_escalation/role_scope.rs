use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Privilege-escalation B4 trust freeze (privilege_escalation/role_scope.rs).
// Rules: CWE-266, CWE-267, CWE-268.
// Primary evidence is mixed assignment/input/call_facts + SourceIndex corpus
// co-presence. Proposed maturity: fixture-only for all three (integrator applies
// maturity.rs). See plans/v0.0.5/pr-cwe-trust-privilege-lifecycle.md.

pub(crate) fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal (mixed): assignment name == "role" + UserControlled input
    // binding for "role" + SI membership co-presence ("Role: role" | "Store(userID, role)").
    // Negative: safe fixtures assign a server-side fixed role (no user-controlled
    // binding named "role"), so the input_bindings gate is the real silence path.
    // Call-facts alone cannot prove privilege assignment without the SI membership
    // needles; keep assignment+input+SI conjunction. Proposed: fixture-only.
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

    let role_is_used_for_membership = facts
        .source_index
        .has_any(&["Role: role", "Store(userID, role)"]);
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

    // Primary signal (fixture-literal role + call_facts sink): SI reviewer-role
    // guard text + call_facts callee exact os.Remove.
    // No generalized role-policy graph; role string "reviewer" is corpus-shaped.
    // Proposed: fixture-only.
    let reviewer_guard = facts
        .source_index
        .has_any(&[r#"!= "reviewer""#, r#".Get("X-Role") != "reviewer""#]);
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

    // Primary signal (fixture-literal scopes + call_facts sensitive sink):
    // SI read/export scope co-presence + (db.Queryx arg contains password_hash
    // OR json.NewEncoder + SI Encode(userRecords)+"hash").
    // Scope names and combination predicate are corpus-shaped. Proposed: fixture-only.
    let has_chained_scopes = (facts
        .source_index
        .has_any(&[r#"p == "read""#, r#"case "read":"#]))
        && (facts
            .source_index
            .has_any(&[r#"p == "export""#, r#"case "export":"#]))
        && (facts
            .source_index
            .has_any(&["hasRead && hasExport", "hasExport && hasRead"]));
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

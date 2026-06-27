use super::super::super::super::common::*;
use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_178(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if facts.source_index.has("strings.EqualFold(") {
        return;
    }

    let Some(assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("strings.ToLower("))
    else {
        return;
    };

    if facts.source_index.has("ReplaceAllString(") {
        return;
    }
    if assignment.expr.contains("strings.TrimSpace(") {
        return;
    }

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
    });
    if !uses_user_input {
        return;
    }

    if !(crate::engine::scratch_contains(source, "[", &assignment.name, "]")
        || crate::engine::scratch_contains(source, "(", &assignment.name, ")"))
    {
        return;
    }

    let (line, col) = unit.line_col(assignment.start_byte);
    emit::push_finding(
        &META_CWE_178,
        file,
        line,
        col,
        "user-controlled lookup key is lowercased and used directly in resource membership checks",
        out,
    );
}

pub(crate) fn detect_cwe_179(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if facts.source_index.has(".MatchString(decoded)") {
        return;
    }

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        if !crate::engine::scratch_contains(source, ".MatchString(", &binding.name, ")") {
            continue;
        }
        if !crate::engine::scratch_contains(source, "url.QueryUnescape(", &binding.name, ")") {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| {
                call.callee.as_ref() == "url.QueryUnescape"
                    && call
                        .arguments
                        .iter()
                        .any(|arg| arg.as_ref() == binding.name.as_ref())
            })
            .map(|call| call.start_byte)
            .unwrap_or(0);

        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_CWE_179,
            file,
            line,
            col,
            "encoded input is validated before URL decoding and then used in decoded form",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_182(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(collapse_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("ReplaceAllString("))
    else {
        return;
    };

    let Some(lower_assignment) = facts.assignments.iter().find(|assignment| {
        assignment.name == collapse_assignment.name && assignment.expr.contains("strings.ToLower(")
    }) else {
        return;
    };

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name == collapse_assignment.name
    });
    if !uses_user_input {
        return;
    }

    if !crate::engine::scratch_contains(source, "[", &lower_assignment.name, "]") {
        return;
    }

    let (line, col) = unit.line_col(collapse_assignment.start_byte);
    emit::push_finding(
        &META_CWE_182,
        file,
        line,
        col,
        "input is stripped and collapsed into an authorization-relevant value before membership checks",
        out,
    );
}

pub(crate) fn detect_cwe_184(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    if facts.source_index.has(".MatchString(") {
        return;
    }

    let Some(lower_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("strings.ToLower("))
    else {
        return;
    };

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && lower_assignment.expr.contains(&*binding.name)
    }) || expression_uses_request_input(&lower_assignment.expr);
    if !uses_user_input {
        return;
    }

    if !(facts.source_index.has("strings.Contains(") && facts.source_index.has("for _, word := range")) {
        return;
    }

    let (line, col) = unit.line_col(lower_assignment.start_byte);
    emit::push_finding(
        &META_CWE_184,
        file,
        line,
        col,
        "user-controlled input is checked against an incomplete deny-list after normalization",
        out,
    );
}

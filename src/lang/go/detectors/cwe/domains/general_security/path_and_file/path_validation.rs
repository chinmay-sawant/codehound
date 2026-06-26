use super::super::super::super::common::*;
use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_41(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let Some(binding) = facts.input_bindings.iter().find(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
        }) else {
            continue;
        };

        if !crate::engine::scratch_contains(
            source,
            r#"strings.Contains("#,
            &binding.name,
            r#", "..")"#,
        ) {
            continue;
        }

        let has_read_sink = facts.call_facts.iter().any(|call| {
            is_path_traversal_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_read_sink {
            continue;
        }

        if has_canonical_path_guard(&facts.source_index, source, &assignment.name) {
            continue;
        }
        if assignment.expr.contains("filepath.Base(") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_41,
            file,
            line,
            col,
            "partial traversal filtering still allows equivalent path aliases to reach file access",
            out,
        );
    }
}

pub(crate) fn detect_cwe_59(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_open_sink = facts.call_facts.iter().any(|call| {
            is_link_resolution_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_open_sink {
            continue;
        }

        if has_symlink_guard(&facts.source_index, source, &assignment.name) {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_59,
            file,
            line,
            col,
            "user-controlled path is opened without a symlink rejection check",
            out,
        );
    }
}

pub(crate) fn detect_cwe_283(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Sys().(*syscall.Stat_t)") || source.contains("stat.Uid") {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Remove")
    else {
        return;
    };
    let removes_user_controlled_path = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && remove_call
                .arguments
                .iter()
                .any(|arg| arg.as_ref() == binding.name.as_ref())
    });
    if !removes_user_controlled_path {
        return;
    }

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_283,
        file,
        line,
        col,
        "a user-selected file path is removed without verifying that the caller owns the inode",
        out,
    );
}

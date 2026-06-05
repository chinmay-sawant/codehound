use super::super::common::*;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_22(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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

        if is_path_confined(&facts.source_index, source, assignment) {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_22,
            file,
            line,
            col,
            "user-controlled path reaches a file-read sink without base-directory confinement",
            out,
        );
    }
}

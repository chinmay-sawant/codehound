use super::super::common::*;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{DetectorEvidence, Finding, emit};
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

        let Some(sink_call) = facts.call_facts.iter().find(|call| {
            is_path_traversal_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        }) else {
            continue;
        };

        if is_path_confined(&facts.source_index, source, assignment) {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        let argument_index = sink_call
            .arguments
            .iter()
            .position(|arg| argument_uses_identifier(arg, &assignment.name));
        emit::push_finding_with_evidence(
            &META_CWE_22,
            file,
            line,
            col,
            "user-controlled path reaches a file-read sink without base-directory confinement",
            DetectorEvidence::DangerousCall {
                function: sink_call.callee.to_string(),
                argument_index,
            },
            out,
        );
    }
}

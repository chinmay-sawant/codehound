use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use super::super::super::taint::detect_cwe_78_taint;
use super::super::super::taint::detect_cwe_89_taint;
use crate::core::ParsedUnit;
use crate::engine::sinks;
use crate::rules::{DetectorEvidence, Finding, emit};

pub(crate) fn detect_cwe_78(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    if facts.taint_graph.is_some() {
        detect_cwe_78_taint(unit, facts, out);
        return;
    }
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if !sinks::matches_sink(&sinks::COMMAND_INJECTION_SINKS, &call.callee)
            || call.arguments.len() < 3
        {
            continue;
        }
        if call.arguments[0].as_ref() != r#""sh""# || call.arguments[1].as_ref() != r#""-c""# {
            continue;
        }

        let payload = &call.arguments[2];
        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && payload.contains(&*binding.name)
                && payload.contains('+')
        });
        if !uses_user_input {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding_with_evidence(
            &META_CWE_78,
            file,
            line,
            col,
            "user-controlled input is interpolated into a shell command string",
            DetectorEvidence::DangerousCall {
                function: call.callee.to_string(),
                argument_index: Some(2),
            },
            out,
        );
    }
}

pub(crate) fn detect_cwe_89(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    if facts.taint_graph.is_some() {
        detect_cwe_89_taint(unit, facts, out);
        return;
    }
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !(assignment.expr.contains("SELECT ")
            || assignment.expr.contains("UPDATE ")
            || assignment.expr.contains("DELETE ")
            || assignment.expr.contains("INSERT "))
        {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let Some(sink_call) = facts.call_facts.iter().find(|call| {
            sinks::matches_sink(&sinks::SQL_SINKS, &call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        }) else {
            continue;
        };

        let (line, col) = unit.line_col(assignment.start_byte);
        let argument_index = sink_call
            .arguments
            .iter()
            .position(|arg| argument_uses_identifier(arg, &assignment.name));
        emit::push_finding_with_evidence(
            &META_CWE_89,
            file,
            line,
            col,
            "user-controlled input is formatted into an SQL query before execution",
            DetectorEvidence::DangerousCall {
                function: sink_call.callee.to_string(),
                argument_index,
            },
            out,
        );
    }
}

pub(crate) fn detect_cwe_90(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !assignment.expr.contains("objectClass=") {
            continue;
        }
        if assignment.expr.contains("escapeLDAP(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_ldap_sink = facts.call_facts.iter().any(|call| {
            call.callee.as_ref() == "dial"
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_ldap_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_90,
            file,
            line,
            col,
            "user-controlled input is formatted into an LDAP filter without escaping",
            out,
        );
    }
}

pub(crate) fn detect_cwe_91(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !(assignment.expr.contains("<profile>") || assignment.expr.contains("<ticket>")) {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&*binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_xml_sink = facts.call_facts.iter().any(|call| {
            call.callee.as_ref() == "xml.Unmarshal"
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_xml_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_91,
            file,
            line,
            col,
            "user-controlled input is formatted directly into XML before parsing",
            out,
        );
    }
}

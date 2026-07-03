use super::super::super::common::argument_uses_identifier;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::{META_CWE_90, META_CWE_91};
use super::super::super::taint::{detect_cwe_78_taint, detect_cwe_89_taint, detect_cwe_90_taint, detect_cwe_91_taint};
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_78(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    detect_cwe_78_taint(unit, facts, out);
}

pub(crate) fn detect_cwe_89(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    detect_cwe_89_taint(unit, facts, out);
}

pub(crate) fn detect_cwe_90(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    if facts.taint_graph.is_some() {
        detect_cwe_90_taint(unit, facts, out);
        return;
    }
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
    if facts.taint_graph.is_some() {
        detect_cwe_91_taint(unit, facts, out);
        return;
    }
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

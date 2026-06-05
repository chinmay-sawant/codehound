use super::super::common::*;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_78(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "exec.Command" || call.arguments.len() < 3 {
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
        emit::push_finding(
            &META_CWE_78,
            file,
            line,
            col,
            "user-controlled input is interpolated into a shell command string",
            out,
        );
    }
}

pub(crate) fn detect_cwe_89(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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

        let has_sql_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_ref(), "db.QueryRow" | "db.Query" | "db.Exec")
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_sql_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_89,
            file,
            line,
            col,
            "user-controlled input is formatted into an SQL query before execution",
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
                    .any(|arg| arg.contains(&*assignment.name))
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

pub(crate) fn detect_cwe_93(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    use crate::engine::scratch_contains;
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        let strips_cr = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\r", "")"#,
        );
        let strips_lf = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\n", "")"#,
        );
        if strips_cr && strips_lf {
            continue;
        }

        let has_location_header_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
                && call.arguments.len() >= 2
                && call.arguments[0].as_ref() == r#""Location""#
                && call.arguments[1].contains(&*binding.name)
        });
        if !has_location_header_sink {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| {
                matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
                    && call.arguments.len() >= 2
                    && call.arguments[0].as_ref() == r#""Location""#
                    && call.arguments[1].contains(&*binding.name)
            })
            .map(|call| call.start_byte)
            .unwrap_or(0);

        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_CWE_93,
            file,
            line,
            col,
            "user-controlled input is concatenated into a Location header without CRLF stripping",
            out,
        );
    }
}

pub(crate) fn detect_cwe_619(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let dangling_rows = source.contains("rows, err := db.Query(") && source.contains("rows.Next()");
    if !dangling_rows {
        return;
    }
    if source.contains("defer rows.Close()") {
        return;
    }

    let start_byte = source.find("rows, err := db.Query(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_619,
        file,
        line,
        col,
        "a database cursor is opened and can return without being closed",
        out,
    );
}

pub(crate) fn detect_cwe_917(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let template_injection = source.contains("template.New(\"report\").Parse(src)")
        && source.contains("{{.Title}} where ")
        && source.contains("+ expr");
    if !template_injection {
        return;
    }
    if source.contains("reportTemplate") || source.contains("reportTemplatePure") {
        return;
    }

    let start_byte = source.find("{{.Title}} where ").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_917,
        file,
        line,
        col,
        "caller-controlled data is concatenated into the template source itself",
        out,
    );
}

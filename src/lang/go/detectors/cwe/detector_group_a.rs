use super::common::*;
use super::facts::{GoUnitFacts, InputKind};
use super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(super) fn detect_cwe_15(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if !is_configuration_sink(&call.callee) {
            continue;
        }

        if !call.arguments.iter().any(|arg| {
            facts.input_bindings.iter().any(|binding| {
                binding.kind == InputKind::UserControlled
                    && argument_uses_identifier(arg, &binding.name)
            })
        }) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_15,
            file,
            line,
            col,
            "request-derived configuration value reaches a database-opening sink",
            out,
        );
    }
}

pub(super) fn detect_cwe_22(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
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

        if is_path_confined(source, assignment) {
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

pub(super) fn detect_cwe_41(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let Some(binding) = facts.input_bindings.iter().find(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
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

        if has_canonical_path_guard(source, &assignment.name) {
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

pub(super) fn detect_cwe_59(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
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

        if has_symlink_guard(source, &assignment.name) {
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

pub(super) fn detect_cwe_76(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("html.EscapeString(") {
        return;
    }
    if !source.contains(r#"strings.ReplaceAll(raw, "<", "")"#)
        || !source.contains(r#"strings.ReplaceAll(safe, ">", "")"#)
    {
        return;
    }
    if !facts
        .input_bindings
        .iter()
        .any(|binding| binding.kind == InputKind::UserControlled && binding.name == "raw")
    {
        return;
    }
    if !source.contains("text/html") {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| {
            assignment.name == "safe" && assignment.expr.contains("strings.ReplaceAll")
        })
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_76,
        file,
        line,
        col,
        "manual angle-bracket stripping is used for HTML output instead of proper escaping",
        out,
    );
}

pub(super) fn detect_cwe_78(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee != "exec.Command" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[0] != r#""sh""# || call.arguments[1] != r#""-c""# {
            continue;
        }

        let payload = &call.arguments[2];
        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && payload.contains(&binding.name)
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

pub(super) fn detect_cwe_79(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("fmt.Sprintf(") || !source.contains("text/html") {
        return;
    }
    if source.contains("html.EscapeString(") {
        return;
    }

    for call in &facts.call_facts {
        if call.callee != "fmt.Sprintf" || call.arguments.is_empty() {
            continue;
        }
        if !call.arguments[0].contains("<html>") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call
                    .arguments
                    .iter()
                    .skip(1)
                    .any(|arg| argument_uses_identifier(arg, &binding.name))
        });
        if !uses_user_input {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_79,
            file,
            line,
            col,
            "user-controlled input is formatted directly into HTML output",
            out,
        );
    }
}

pub(super) fn detect_cwe_89(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_sql_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_str(), "db.QueryRow" | "db.Query" | "db.Exec")
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

pub(super) fn detect_cwe_90(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_ldap_sink = facts.call_facts.iter().any(|call| {
            call.callee == "dial"
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

pub(super) fn detect_cwe_91(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !(assignment.expr.contains("<profile>") || assignment.expr.contains("<ticket>")) {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_xml_sink = facts.call_facts.iter().any(|call| {
            call.callee == "xml.Unmarshal"
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.contains(&assignment.name))
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

pub(super) fn detect_cwe_93(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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
            matches!(call.callee.as_str(), "c.Header" | "w.Header().Set")
                && call.arguments.len() >= 2
                && call.arguments[0] == r#""Location""#
                && call.arguments[1].contains(&binding.name)
        });
        if !has_location_header_sink {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| {
                matches!(call.callee.as_str(), "c.Header" | "w.Header().Set")
                    && call.arguments.len() >= 2
                    && call.arguments[0] == r#""Location""#
                    && call.arguments[1].contains(&binding.name)
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

pub(super) fn detect_cwe_112(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_xml_unmarshal = facts
        .call_facts
        .iter()
        .any(|call| call.callee == "xml.Unmarshal")
        || source.contains("xml.Unmarshal(");
    if !has_xml_unmarshal {
        return;
    }

    let has_untrusted_payload = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && crate::engine::scratch_contains(source, "xml.Unmarshal(", &binding.name, ",")
    });
    if !has_untrusted_payload {
        return;
    }

    let has_validation = source.contains(".MatchString(") || source.contains(" <= 0");
    if has_validation {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "xml.Unmarshal")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_112,
        file,
        line,
        col,
        "untrusted XML is unmarshaled without subsequent field-level validation",
        out,
    );
}

pub(super) fn detect_cwe_140(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("text/csv") {
        return;
    }
    if source.contains("csv.NewWriter(") {
        return;
    }
    if !source.contains("strings.Join(") || !source.contains("\",\"") {
        return;
    }

    let uses_user_input = facts
        .input_bindings
        .iter()
        .any(|binding| binding.kind == InputKind::UserControlled && source.contains(&binding.name));
    if !uses_user_input {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("strings.Join(") || assignment.name == "line")
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_140,
        file,
        line,
        col,
        "user-controlled fields are joined into CSV output with literal delimiters",
        out,
    );
}

pub(super) fn detect_cwe_178(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("strings.EqualFold(") {
        return;
    }

    let Some(assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("strings.ToLower("))
    else {
        return;
    };

    if source.contains("ReplaceAllString(") {
        return;
    }
    if assignment.expr.contains("strings.TrimSpace(") {
        return;
    }

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
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

pub(super) fn detect_cwe_179(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains(".MatchString(decoded)") {
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
                call.callee == "url.QueryUnescape"
                    && call.arguments.iter().any(|arg| arg == &binding.name)
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

pub(super) fn detect_cwe_182(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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

pub(super) fn detect_cwe_184(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains(".MatchString(") {
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
        binding.kind == InputKind::UserControlled && lower_assignment.expr.contains(&binding.name)
    }) || expression_uses_request_input(&lower_assignment.expr);
    if !uses_user_input {
        return;
    }

    if !(source.contains("strings.Contains(") && source.contains("for _, word := range")) {
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

pub(super) fn detect_cwe_186(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("regexp.MustCompile(`^[a-z]+$`)") {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "regexp.MustCompile")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_186,
        file,
        line,
        col,
        "host validation uses an overly restrictive regex that only accepts lowercase letters",
        out,
    );
}

pub(super) fn detect_cwe_201(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_sensitive_field = source.contains("APIKey") || source.contains("TokenKey");
    if !has_sensitive_field {
        return;
    }

    let sensitive_record_name = if source.contains("type userRecord struct")
        || source.contains("type memberRecord struct")
    {
        Some("record")
    } else {
        None
    };
    let Some(record_name) = sensitive_record_name else {
        return;
    };

    let direct_json_response = facts.call_facts.iter().find(|call| {
        (call.callee == "c.JSON" || call.callee == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg == record_name)
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

pub(super) fn detect_cwe_204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_missing_account_branch =
        source.contains("no account") && source.contains("StatusNotFound");
    let has_wrong_secret_branch = source.contains("bad password")
        || source.contains("bad secret")
        || source.contains("StatusUnauthorized");
    let has_uniform_failure = source.contains("invalid credentials");

    if !(has_missing_account_branch && has_wrong_secret_branch) || has_uniform_failure {
        return;
    }

    let start_byte = source.find("no account").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_204,
        file,
        line,
        col,
        "authentication failures return distinguishable responses for missing accounts and wrong credentials",
        out,
    );
}

pub(super) fn detect_cwe_208(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("subtle.ConstantTimeCompare(") {
        return;
    }
    if !(source.contains("for i := range expected")
        && source.contains("provided[i] != expected[i]"))
    {
        return;
    }

    let start_byte = source.find("for i := range expected").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_208,
        file,
        line,
        col,
        "secret comparison returns early on mismatched bytes instead of using a constant-time primitive",
        out,
    );
}

pub(super) fn detect_cwe_209(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(r#"fmt.Sprintf("db failure: %v", err)"#) {
        return;
    }

    let start_byte = source
        .find(r#"fmt.Sprintf("db failure: %v", err)"#)
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_209,
        file,
        line,
        col,
        "database error details are formatted into a client-facing response",
        out,
    );
}

pub(super) fn detect_cwe_212(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_sensitive_payment_field = source.contains("Card") || source.contains("PAN");
    if !has_sensitive_payment_field {
        return;
    }
    if !(source.contains("json.Marshal(rows)") || source.contains("json.Marshal(out)")) {
        return;
    }
    if source.contains("type paymentExport struct") || source.contains("type chargeExport struct") {
        return;
    }
    if !source.contains("json.Marshal(rows)") {
        return;
    }

    let start_byte = source.find("json.Marshal(rows)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_212,
        file,
        line,
        col,
        "records containing sensitive payment fields are marshaled directly for export",
        out,
    );
}

pub(super) fn detect_cwe_213(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_comp_field = source.contains("Salary") || source.contains("Comp");
    if !has_comp_field {
        return;
    }
    if source.contains("guestProfile{") || source.contains("directoryEntry{") {
        return;
    }

    let direct_profile_response = facts.call_facts.iter().find(|call| {
        (call.callee == "c.JSON" || call.callee == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg == "profile")
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

pub(super) fn detect_cwe_214(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee != "exec.Command" {
            continue;
        }
        if source.contains("cmd.Stdin = strings.NewReader(") {
            return;
        }

        let uses_user_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call.arguments.iter().any(|arg| arg == &binding.name)
                && call.arguments.iter().any(|arg| arg == r#""--token""#)
        });
        if !uses_user_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_214,
            file,
            line,
            col,
            "a user-supplied token is passed as a visible argv argument to an external process",
            out,
        );
        return;
    }
}

pub(super) fn detect_cwe_215(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee != "log.Printf" {
            continue;
        }

        let logs_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && binding.name.contains("secret")
                && call.arguments.iter().any(|arg| arg == &binding.name)
        });
        if !logs_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_215,
            file,
            line,
            col,
            "a debug log statement includes request-derived secret material",
            out,
        );
        return;
    }
}

pub(super) fn detect_cwe_250(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee != "os.WriteFile" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[2] != "0o777" {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_250,
            file,
            line,
            col,
            "runtime file is written with world-accessible permissions",
            out,
        );
        return;
    }
}

pub(super) fn detect_cwe_252(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee != "os.WriteFile" {
            continue;
        }
        if source.contains("if err := os.WriteFile(") {
            return;
        }
        let writes_audit_log = call
            .arguments
            .iter()
            .any(|arg| arg.contains("/var/log/audit.log") || arg.contains("/var/log/journal.log"));
        if !writes_audit_log {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_252,
            file,
            line,
            col,
            "os.WriteFile is called without checking its returned error",
            out,
        );
        return;
    }
}

pub(super) fn detect_cwe_256(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("GenerateFromPassword(")
        || source.contains("hashPassphrase(")
        || source.contains("digest")
        || source.contains("hash")
    {
        return;
    }

    let gorm_plaintext = source.contains("Password: c.PostForm(\"password\")");
    let sql_plaintext = source
        .contains("db.Exec(\"INSERT INTO credentials(login, pass) VALUES(?, ?)\", login, pass)");
    if !(gorm_plaintext || sql_plaintext) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Password: c.PostForm(\"password\")") {
        idx
    } else {
        source
            .find("db.Exec(\"INSERT INTO credentials(login, pass) VALUES(?, ?)\", login, pass)")
            .unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_256,
        file,
        line,
        col,
        "a plaintext password value is persisted directly instead of a hash or digest",
        out,
    );
}

pub(super) fn detect_cwe_257(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let uses_reversible_crypto = source.contains("aes.NewCipher(")
        && source.contains("cipher.NewGCM(")
        && source.contains("gcm.Seal(")
        && source.contains("base64.StdEncoding.EncodeToString(");
    if !uses_reversible_crypto {
        return;
    }

    let persists_recoverable_secret = source.contains(r#""password": encoded"#)
        || source.contains("VALUES(?, ?)\", login, encoded)");
    if !persists_recoverable_secret {
        return;
    }

    let start_byte = source.find("aes.NewCipher(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_257,
        file,
        line,
        col,
        "a password or login secret is encrypted with a reversible cipher before storage",
        out,
    );
}

pub(super) fn detect_cwe_260(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let config_type_has_secret_field =
        source.contains("Password string") || source.contains("Secret   string");
    if !config_type_has_secret_field {
        return;
    }
    if source.contains("os.Getenv(") {
        return;
    }
    if !(source.contains("cfg.Password") || source.contains("cfg.Secret")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("cfg.Password") {
        idx
    } else {
        source.find("cfg.Secret").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_260,
        file,
        line,
        col,
        "a secret-bearing field is loaded from a configuration file and used directly",
        out,
    );
}

pub(super) fn detect_cwe_261(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("base64.StdEncoding.EncodeToString(") {
        return;
    }
    let stores_encoded_secret =
        source.contains("Secret: encoded") || source.contains("Store(user, encoded)");
    if !stores_encoded_secret {
        return;
    }

    let start_byte = source
        .find("base64.StdEncoding.EncodeToString(")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_261,
        file,
        line,
        col,
        "a password is Base64-encoded and then stored in a recoverable form",
        out,
    );
}

pub(super) fn detect_cwe_262(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loads_age_metadata = source.contains("last_seen") || source.contains("changed_at");
    if !loads_age_metadata {
        return;
    }
    if source.contains("time.Since(") || source.contains("maxPasswordAge") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("last_seen") {
        idx
    } else {
        source.find("changed_at").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_262,
        file,
        line,
        col,
        "credential metadata is loaded but no password-age enforcement is performed",
        out,
    );
}

pub(super) fn detect_cwe_263(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("MaxAgeDays: 3650") {
        return;
    }

    let start_byte = source.find("MaxAgeDays: 3650").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_263,
        file,
        line,
        col,
        "password maximum age is configured to an excessively long multi-year period",
        out,
    );
}

pub(super) fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(role_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.name == "role")
    else {
        return;
    };

    let role_is_user_controlled = facts
        .input_bindings
        .iter()
        .any(|binding| binding.kind == InputKind::UserControlled && binding.name == "role");
    if !role_is_user_controlled {
        return;
    }

    let role_is_used_for_membership =
        source.contains("Role: role") || source.contains("Store(userID, role)");
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

pub(super) fn detect_cwe_267(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reviewer_guard =
        source.contains(r#"!= "reviewer""#) || source.contains(r#".Get("X-Role") != "reviewer""#);
    if !reviewer_guard {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "os.Remove")
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

pub(super) fn detect_cwe_268(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_chained_scopes = (source.contains(r#"p == "read""#)
        || source.contains(r#"case "read":"#))
        && (source.contains(r#"p == "export""#) || source.contains(r#"case "export":"#))
        && (source.contains("hasRead && hasExport") || source.contains("hasExport && hasRead"));
    if !has_chained_scopes {
        return;
    }

    let Some(sensitive_sink) = facts.call_facts.iter().find(|call| {
        (call.callee == "db.Queryx"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("password_hash")))
            || (call.callee == "json.NewEncoder"
                && source.contains("Encode(userRecords)")
                && source.contains(r#""hash""#))
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

pub(super) fn detect_cwe_270(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(context_switch) = facts.call_facts.iter().find(|call| {
        (call.callee == "c.Set"
            && call.arguments.len() >= 2
            && call.arguments[0].contains("effective_user")
            && (call.arguments[1].contains(r#""root""#)
                || call.arguments[1].contains(r#""maintenance""#)))
            || (call.callee == "context.WithValue"
                && call.arguments.len() >= 3
                && call.arguments[1].contains("effectiveUserKey")
                && (call.arguments[2].contains(r#""root""#)
                    || call.arguments[2].contains(r#""maintenance""#)))
    }) else {
        return;
    };

    let restores_context = source.contains("defer c.Set(\"effective_user\", original)")
        || (source.contains("defer func()")
            && source.contains("context.WithValue(r.Context(), effectiveUserKey, original)"));
    if restores_context {
        return;
    }

    let (line, col) = unit.line_col(context_switch.start_byte);
    emit::push_finding(
        &META_CWE_270,
        file,
        line,
        col,
        "the handler switches to a privileged execution context without restoring the original caller context",
        out,
    );
}

pub(super) fn detect_cwe_272(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(elevate_call) = facts.call_facts.iter().find(|call| {
        call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "0")
    }) else {
        return;
    };

    let performs_privileged_work = facts
        .call_facts
        .iter()
        .any(|call| call.callee == "os.Chown");
    if !performs_privileged_work {
        return;
    }

    let drops_privilege = facts.call_facts.iter().any(|call| {
        call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "1000")
    });
    if drops_privilege {
        return;
    }

    let (line, col) = unit.line_col(elevate_call.start_byte);
    emit::push_finding(
        &META_CWE_272,
        file,
        line,
        col,
        "the handler raises uid for a privileged operation and does not drop it afterward",
        out,
    );
}

pub(super) fn detect_cwe_273(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("if err := syscall.Setuid(1000); err != nil") {
        return;
    }

    if facts.call_facts.iter().any(|call| {
        call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "0")
    }) {
        return;
    }

    let Some(drop_call) = facts.call_facts.iter().find(|call| {
        call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "1000")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(drop_call.start_byte);
    emit::push_finding(
        &META_CWE_273,
        file,
        line,
        col,
        "the handler ignores whether dropping privilege via Setuid actually succeeded",
        out,
    );
}

pub(super) fn detect_cwe_274(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(rename_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "os.Rename")
    else {
        return;
    };

    let treats_error_as_success = (source.contains("if err != nil {")
        && (source.contains(r#"c.JSON(200, gin.H{"rotated": true})"#)
            || source.contains(r#"w.WriteHeader(http.StatusOK)"#)))
        && !source.contains("errors.Is(err, syscall.EPERM)");
    if !treats_error_as_success {
        return;
    }

    let (line, col) = unit.line_col(rename_call.start_byte);
    emit::push_finding(
        &META_CWE_274,
        file,
        line,
        col,
        "an insufficient-privilege filesystem failure is treated like a successful rotation",
        out,
    );
}

pub(super) fn detect_cwe_276(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2] == "0666"
            && (call.arguments[0].contains("sessions")
                || source.contains("session_data")
                || source.contains("X-Session-Data"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_276,
        file,
        line,
        col,
        "a session artifact is written with a world-readable and world-writable default mode",
        out,
    );
}

pub(super) fn detect_cwe_277(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let clears_umask = facts.call_facts.iter().any(|call| {
        call.callee == "syscall.Umask" && call.arguments.first().is_some_and(|arg| arg == "0")
    });
    if !clears_umask {
        return;
    }

    let Some(mkdir_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.MkdirAll" && call.arguments.len() >= 2 && call.arguments[1] == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(mkdir_call.start_byte);
    emit::push_finding(
        &META_CWE_277,
        file,
        line,
        col,
        "umask is cleared before creating a world-writable directory",
        out,
    );
}

pub(super) fn detect_cwe_278(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(open_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.OpenFile"
            && call.arguments.len() >= 3
            && call.arguments[2].contains("os.FileMode(hdr.Mode)")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_278,
        file,
        line,
        col,
        "archive entry permissions are reapplied directly from untrusted metadata during extraction",
        out,
    );
}

pub(super) fn detect_cwe_279(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("strconv.ParseUint(") {
        return;
    }

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.WriteFile" && call.arguments.len() >= 3 && call.arguments[2] == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_279,
        file,
        line,
        col,
        "the handler parses a requested mode but still writes the file with a hard-coded world-writable mode",
        out,
    );
}

pub(super) fn detect_cwe_280(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(open_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "os.Open")
    else {
        return;
    };

    let falls_through_on_error = source.contains("if err != nil {")
        && !source.contains("errors.Is(err, syscall.EACCES)")
        && !source.contains("errors.Is(err, syscall.EPERM)")
        && (source.contains("db.Exec(\"DELETE FROM tenants")
            || source.contains("tenantStore.Delete("));
    if !falls_through_on_error {
        return;
    }

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_280,
        file,
        line,
        col,
        "failure to access a protected resource leads into a privileged deletion path instead of a denial",
        out,
    );
}

pub(super) fn detect_cwe_281(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Mode()") {
        return;
    }

    let Some(create_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "os.Create")
    else {
        return;
    };

    if !source.contains("io.Copy(out, in)") {
        return;
    }

    let (line, col) = unit.line_col(create_call.start_byte);
    emit::push_finding(
        &META_CWE_281,
        file,
        line,
        col,
        "backup recreation uses os.Create and loses the source file's original permission bits",
        out,
    );
}

pub(super) fn detect_cwe_283(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Sys().(*syscall.Stat_t)") || source.contains("stat.Uid") {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "os.Remove")
    else {
        return;
    };
    let removes_user_controlled_path = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && remove_call.arguments.iter().any(|arg| arg == &binding.name)
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

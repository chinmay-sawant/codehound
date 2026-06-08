use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_112(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_xml_unmarshal = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "xml.Unmarshal")
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
        .find(|call| call.callee.as_ref() == "xml.Unmarshal")
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

pub(crate) fn detect_cwe_178(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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
        binding.kind == InputKind::UserControlled && lower_assignment.expr.contains(&*binding.name)
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

pub(crate) fn detect_cwe_611(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unsafe_xml = source.contains("xml.NewDecoder(")
        && source.contains("dec.Strict = false")
        && source.contains("Decode(&catalog)");
    if !unsafe_xml {
        return;
    }
    if source.contains("<!DOCTYPE")
        || source.contains("dec.Strict = true")
        || source.contains("LimitReader")
    {
        return;
    }

    let start_byte = source.find("dec.Strict = false").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_611,
        file,
        line,
        col,
        "untrusted XML is parsed with strict mode disabled and no DOCTYPE rejection",
        out,
    );
}

pub(crate) fn detect_cwe_838(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let invalid_utf8 =
        source.contains("application/json; charset=utf-8") && source.contains("0xC3, 0x28");
    if !invalid_utf8 {
        return;
    }

    let start_byte = source.find("0xC3, 0x28").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_838,
        file,
        line,
        col,
        "invalid byte sequences are emitted while declaring UTF-8 JSON output",
        out,
    );
}

pub(crate) fn detect_cwe_1286(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loose_json_config = (source.contains("SaveHookConfig(")
        || source.contains("SaveHookConfigPure("))
        && (source.contains("json.Unmarshal(body, &cfg)")
            || source.contains("json.NewDecoder(r.Body).Decode(&cfg)"))
        && source.contains("hook_configs");
    if !loose_json_config {
        return;
    }
    if source.contains("DisallowUnknownFields()") || source.contains("ParseRequestURI(cfg.URL)") {
        return;
    }

    let start_byte = source
        .find("json.Unmarshal(body, &cfg)")
        .or_else(|| source.find("json.NewDecoder(r.Body).Decode(&cfg)"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1286,
        file,
        line,
        col,
        "webhook configuration JSON is accepted without strict syntax and URL validation",
        out,
    );
}

pub(crate) fn detect_cwe_1389(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let implicit_radix = (source.contains("ReserveSeats(") || source.contains("ReserveSeatsPure("))
        && source.contains("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if source.contains("strconv.ParseInt(raw, 10, 64)") {
        return;
    }

    let start_byte = source.find("strconv.ParseInt(raw, 0, 64)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1389,
        file,
        line,
        col,
        "seat counts are parsed with base 0 and may accept alternate-radix prefixes unexpectedly",
        out,
    );
}

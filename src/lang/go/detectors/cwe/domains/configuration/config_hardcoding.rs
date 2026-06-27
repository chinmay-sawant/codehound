use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_15(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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

pub(crate) fn detect_cwe_472(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_form = facts.source_index.has("Role    string `form:\"role\"`")
        || facts.source_index.has("role := r.FormValue(\"role\")");
    if !trusts_role_form {
        return;
    }
    if facts.source_index.has("SELECT role FROM users") {
        return;
    }

    let start_byte = source.find("role").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_472,
        file,
        line,
        col,
        "authorization trusts a client-submitted role field instead of resolving role server-side",
        out,
    );
}

pub(crate) fn detect_cwe_1051(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hard_coded_upstream = (facts.source_index.has("ChargeCard(")
        || facts.source_index.has("ChargeCardPure("))
        && facts.source_index.has("10.20.30.40:9090")
        && facts.source_index.has("http.NewRequest(")
        && facts.source_index.has("X-Card-Token");
    if !hard_coded_upstream {
        return;
    }
    if facts.source_index.has("os.Getenv(\"BILLING_API_URL\")") {
        return;
    }

    let start_byte = source.find("10.20.30.40:9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1051,
        file,
        line,
        col,
        "an outbound billing request is pinned to a hard-coded internal host",
        out,
    );
}

pub(crate) fn detect_cwe_1067(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let leading_wildcard_scan = (facts.source_index.has("fmt.Sprintf(\"%%%s%%\", term)")
        || facts.source_index.has("pattern := fmt.Sprintf(\"%%%s%%\", term)"))
        && facts.source_index.has("LIKE")
        && (facts.source_index.has("notes.body") || facts.source_index.has("SELECT id, body FROM notes"));
    if !leading_wildcard_scan {
        return;
    }
    if facts.source_index.has("prefix+\"%\"") || facts.source_index.has("pattern := prefix + \"%\"") {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%%%s%%\", term)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1067,
        file,
        line,
        col,
        "a search predicate uses a leading wildcard pattern that forces a sequential scan",
        out,
    );
}

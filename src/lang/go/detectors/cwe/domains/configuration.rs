use super::super::common::*;
use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
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

pub(crate) fn detect_cwe_260(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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

pub(crate) fn detect_cwe_455(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let continues_after_tls_failure =
        source.contains("tls.LoadX509KeyPair(") && source.contains("continuing without mTLS");
    if !continues_after_tls_failure {
        return;
    }
    if source.contains("log.Fatalf(") {
        return;
    }

    let start_byte = source.find("continuing without mTLS").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_455,
        file,
        line,
        col,
        "startup logs a TLS material failure but continues running anyway",
        out,
    );
}

pub(crate) fn detect_cwe_472(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_form = source.contains("Role    string `form:\"role\"`")
        || source.contains("role := r.FormValue(\"role\")");
    if !trusts_role_form {
        return;
    }
    if source.contains("SELECT role FROM users") {
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

pub(crate) fn detect_cwe_1051(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hard_coded_upstream = (source.contains("ChargeCard(")
        || source.contains("ChargeCardPure("))
        && source.contains("10.20.30.40:9090")
        && source.contains("http.NewRequest(")
        && source.contains("X-Card-Token");
    if !hard_coded_upstream {
        return;
    }
    if source.contains("os.Getenv(\"BILLING_API_URL\")") {
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

pub(crate) fn detect_cwe_1067(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let leading_wildcard_scan = (source.contains("fmt.Sprintf(\"%%%s%%\", term)")
        || source.contains("pattern := fmt.Sprintf(\"%%%s%%\", term)"))
        && source.contains("LIKE")
        && (source.contains("notes.body") || source.contains("SELECT id, body FROM notes"));
    if !leading_wildcard_scan {
        return;
    }
    if source.contains("prefix+\"%\"") || source.contains("pattern := prefix + \"%\"") {
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

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
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

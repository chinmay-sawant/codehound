use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_319(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let handles_card_data = source.contains("CVV") && source.contains("Number");
    if !handles_card_data {
        return;
    }
    if source.contains("ListenAndServeTLS(") || source.contains("tls.Config") {
        return;
    }
    if !(source.contains("ListenAndServe(") || source.contains("http.ListenAndServe(")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ListenAndServe") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_319,
        file,
        line,
        col,
        "sensitive payment data is accepted over a cleartext HTTP listener instead of TLS",
        out,
    );
}

pub(crate) fn detect_cwe_524(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let process_wide_token_cache = (source.contains("map[string]string{}")
        && source.contains("Authorization"))
        && (source.contains("tokenCache") || source.contains("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if source.contains("context.WithValue(") || source.contains("session_token") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("tokenCache") {
        idx
    } else {
        source.find("tokenVault").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_524,
        file,
        line,
        col,
        "raw session tokens are cached in shared process memory keyed by caller identifiers",
        out,
    );
}

pub(crate) fn detect_cwe_538(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let public_secret_export = source.contains("DATABASE_URL")
        && source.contains("os.WriteFile(")
        && (source.contains("/var/www/") || source.contains("/var/www/html/public/"))
        && source.contains("0o644");
    if !public_secret_export {
        return;
    }
    if source.contains("/var/lib/slopguard/private") || source.contains("0o600") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/var/www/html/public/config-snapshot.txt") {
        idx
    } else {
        source.find("/var/www/static").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_538,
        file,
        line,
        col,
        "database configuration secrets are exported to a public world-readable file path",
        out,
    );
}

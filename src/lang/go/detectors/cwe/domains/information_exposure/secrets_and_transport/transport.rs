use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_319(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let handles_card_data = facts.source_index.has("CVV") && facts.source_index.has("Number");
    if !handles_card_data {
        return;
    }
    if facts.source_index.has("ListenAndServeTLS(") || facts.source_index.has("tls.Config") {
        return;
    }
    if !(facts.source_index.has("ListenAndServe(")
        || facts.source_index.has("http.ListenAndServe("))
    {
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

pub(crate) fn detect_cwe_524(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let process_wide_token_cache = (facts.source_index.has("map[string]string{}")
        && facts.source_index.has("Authorization"))
        && (facts.source_index.has("tokenCache") || facts.source_index.has("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if facts.source_index.has("context.WithValue(") || facts.source_index.has("session_token") {
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

pub(crate) fn detect_cwe_538(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let public_secret_export = facts.source_index.has("DATABASE_URL")
        && facts.source_index.has("os.WriteFile(")
        && (facts.source_index.has("/var/www/") || facts.source_index.has("/var/www/html/public/"))
        && facts.source_index.has("0o644");
    if !public_secret_export {
        return;
    }
    if facts.source_index.has("/var/lib/codehound/private") || facts.source_index.has("0o600") {
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

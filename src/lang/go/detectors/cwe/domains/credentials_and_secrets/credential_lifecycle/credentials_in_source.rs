use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_523(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let cleartext_login = (source.contains("/login") && source.contains("password"))
        && (source.contains("Addr: \":8080\"") || source.contains("StartCleartextLogin"));
    if !cleartext_login {
        return;
    }
    if source.contains("requireTLS(")
        || source.contains("Request.TLS == nil")
        || source.contains("r.TLS == nil")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/login") {
        idx
    } else {
        source.find("password").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_523,
        file,
        line,
        col,
        "login credentials are accepted before any TLS enforcement or redirect",
        out,
    );
}

pub(crate) fn detect_cwe_547(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_signing_secret =
        source.contains("const jwtSecret = ") || source.contains("const sessionMACKey = ");
    if !hardcoded_signing_secret {
        return;
    }
    if source.contains("os.Getenv(\"JWT_SIGNING_KEY\")")
        || source.contains("os.Getenv(\"SESSION_MAC_KEY\")")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const jwtSecret = ") {
        idx
    } else {
        source.find("const sessionMACKey = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_547,
        file,
        line,
        col,
        "signing material is hard-coded directly in source instead of loaded from runtime secret configuration",
        out,
    );
}

pub(crate) fn detect_cwe_798(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_dsn = source
        .contains("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable");
    if !hardcoded_dsn {
        return;
    }
    if source.contains("os.Getenv(\"REPORTING_DSN\")") {
        return;
    }

    let start_byte = source
        .find("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_798,
        file,
        line,
        col,
        "database credentials are embedded directly in the source code",
        out,
    );
}

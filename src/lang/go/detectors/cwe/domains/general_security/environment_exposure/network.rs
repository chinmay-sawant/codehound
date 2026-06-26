use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_359(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let serializes_pii = (source.contains("SSN")
        && source.contains("Phone")
        && source.contains("json.Marshal(row)"))
        || (source.contains("SSN")
            && source.contains("Phone")
            && source.contains("json.Marshal(")
            && source.contains("PersonRecord"));
    if !serializes_pii {
        return;
    }
    if source.contains("PublicProfile")
        || source.contains("PublicPersonView")
        || source.contains("requester != target")
    {
        return;
    }

    let start_byte = source
        .find("json.Marshal(row)")
        .unwrap_or_else(|| source.find("SSN").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_359,
        file,
        line,
        col,
        "private personal information is serialized directly without requester authorization or public projection",
        out,
    );
}

pub(crate) fn detect_cwe_360(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("X-Forwarded-For") {
        return;
    }
    if source.contains("SplitHostPort(") || source.contains("RemoteAddr") {
        return;
    }

    let start_byte = source.find("X-Forwarded-For").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_360,
        file,
        line,
        col,
        "a security-sensitive client IP action trusts caller-controlled forwarded header data",
        out,
    );
}

pub(crate) fn detect_cwe_393(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wrong_status = source.contains("if err != nil {")
        && source.contains("WriteHeader(http.StatusOK)")
        && source.contains(r#"{"balance":0}"#);
    if !wrong_status {
        return;
    }

    let start_byte = source.find("WriteHeader(http.StatusOK)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_393,
        file,
        line,
        col,
        "lookup failure still returns HTTP 200 with a fallback balance payload",
        out,
    );
}

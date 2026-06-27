use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_515(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_covert_flag = (facts
        .source_index
        .has_any(&["var quotaFlag int", "var quotaCovertFlag int"]))
        && facts.source_index.has(r#""over""#)
        && facts.source_index.has("= 1")
        && facts.source_index.has("= 0")
        && facts.source_index.has(r#""over_limit""#);
    if !shared_covert_flag {
        return;
    }
    if facts
        .source_index
        .has_any(&["WHERE tenant = ?", r#"GetString("tenant")"#, "X-Tenant"])
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("var quotaFlag int") {
        idx
    } else {
        source.find("var quotaCovertFlag int").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_515,
        file,
        line,
        col,
        "a global quota flag is used as a covert cross-request signal",
        out,
    );
}

pub(crate) fn detect_cwe_544(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let inconsistent_db_failure_paths = (facts.source_index.has_any(&[
        "panic(err)",
        "panic(err)
",
    ])) && facts.source_index.has("log.Println(err)")
        && (facts.source_index.has_any(&["db.Get(", "db.QueryRow("]));
    if !inconsistent_db_failure_paths {
        return;
    }
    if facts
        .source_index
        .has_any(&["writeDBError(", "writeDBFailure("])
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("panic(err)") {
        idx
    } else {
        source.find("log.Println(err)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_544,
        file,
        line,
        col,
        "database failures are handled through inconsistent panic and logging paths",
        out,
    );
}

pub(crate) fn detect_cwe_605(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("SO_REUSEADDR") || !facts.source_index.has("SetsockoptInt") {
        return;
    }
    if facts.source_index.has(r#"net.Listen("tcp", ":9090")"#) {
        return;
    }

    let start_byte = source.find("SO_REUSEADDR").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_605,
        file,
        line,
        col,
        "the listener explicitly enables SO_REUSEADDR on the service socket",
        out,
    );
}

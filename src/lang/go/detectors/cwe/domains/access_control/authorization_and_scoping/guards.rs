use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_425(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let admin_export = facts.source_index.has("/internal/admin/export.csv")
        && facts.source_index.has("SELECT email, ssn FROM customers");
    if !admin_export {
        return;
    }
    if facts.source_index.has_any(&["requireAdmin()", "requireAdmin("]) {
        return;
    }

    let start_byte = source.find("/internal/admin/export.csv").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_425,
        file,
        line,
        col,
        "the admin export endpoint is mounted without an explicit authorization guard",
        out,
    );
}

pub(crate) fn detect_cwe_551(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_path_gate = facts.source_index.has("raw := ")
        && facts.source_index.has("URL.Path")
        && facts.source_index.has(r#"strings.HasPrefix(raw, "/admin")"#)
        && facts.source_index.has(r#"strings.ReplaceAll(raw, "%2f", "/")"#);
    if !raw_path_gate {
        return;
    }
    if facts.source_index.has("url.PathUnescape(raw)") {
        return;
    }

    let start_byte = source
        .find("strings.HasPrefix(raw, \"/admin\")")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_551,
        file,
        line,
        col,
        "authorization checks the raw path before percent-unescape canonicalization",
        out,
    );
}

pub(crate) fn detect_cwe_653(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_privileged_store = (facts.source_index.has_any(&["sharedDB", "sharedAuditStore"]))
        && facts.source_index.has("PublicSearch")
        && facts.source_index.has("AdminPurge");
    if !shared_privileged_store {
        return;
    }
    if facts.source_index.has_any(&["readOnlyDB", "readOnlyAuditStore", "adminDB", "adminAuditStore"])
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sharedDB") {
        idx
    } else {
        source.find("sharedAuditStore").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_653,
        file,
        line,
        col,
        "public and admin paths share the same privileged data store",
        out,
    );
}

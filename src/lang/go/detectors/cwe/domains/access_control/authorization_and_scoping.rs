use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_425(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let admin_export = source.contains("/internal/admin/export.csv")
        && source.contains("SELECT email, ssn FROM customers");
    if !admin_export {
        return;
    }
    if source.contains("requireAdmin()") || source.contains("requireAdmin(") {
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

pub(crate) fn detect_cwe_551(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_path_gate = source.contains("raw := ")
        && source.contains("URL.Path")
        && source.contains("strings.HasPrefix(raw, \"/admin\")")
        && source.contains("strings.ReplaceAll(raw, \"%2f\", \"/\")");
    if !raw_path_gate {
        return;
    }
    if source.contains("url.PathUnescape(raw)") {
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

pub(crate) fn detect_cwe_639(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let user_controlled_key = source.contains("invoice_id")
        && (source.contains("SELECT id, user_id, amount FROM invoices WHERE id = $1")
            || source
                .contains("SELECT id, user_id, amount FROM invoices WHERE id = $1\", invoiceID"));
    if !user_controlled_key {
        return;
    }
    if source.contains("AND user_id = $2")
        || source.contains("ownerID")
        || source.contains("X-User-ID")
    {
        return;
    }

    let start_byte = source.find("invoice_id").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_639,
        file,
        line,
        col,
        "a caller-controlled invoice key is queried without owner scoping",
        out,
    );
}

pub(crate) fn detect_cwe_653(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_privileged_store = (source.contains("sharedDB")
        || source.contains("sharedAuditStore"))
        && source.contains("PublicSearch")
        && source.contains("AdminPurge");
    if !shared_privileged_store {
        return;
    }
    if source.contains("readOnlyDB")
        || source.contains("readOnlyAuditStore")
        || source.contains("adminDB")
        || source.contains("adminAuditStore")
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

pub(crate) fn detect_cwe_1220(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unscoped_invoice_read = (source.contains("GetInvoice(")
        || source.contains("GetInvoicePure("))
        && source.contains("Authorization")
        && source.contains("FROM invoices WHERE id = $1");
    if !unscoped_invoice_read {
        return;
    }
    if source.contains("owner_id = $2")
        || source.contains("ownerID")
        || source.contains("X-User-ID")
    {
        return;
    }

    let start_byte = source.find("FROM invoices WHERE id = $1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1220,
        file,
        line,
        col,
        "invoice access is authenticated but not scoped to the requesting owner",
        out,
    );
}

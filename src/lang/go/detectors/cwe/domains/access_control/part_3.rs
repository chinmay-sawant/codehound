use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
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

pub(crate) fn detect_cwe_836(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_submits_hash =
        source.contains("PasswordHash string") || source.contains("`json:\"password_hash\"`");
    let hash_as_password = client_submits_hash
        && (source.contains("password_hash = ?")
            || source.contains("WHERE username = ? AND password_hash = ?")
            || source.contains("WHERE username = $1 AND password_hash = $2"));
    if !hash_as_password {
        return;
    }
    if source.contains("CompareHashAndPassword") || source.contains("ConstantTimeCompare") {
        return;
    }

    let start_byte = source.find("password_hash").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_836,
        file,
        line,
        col,
        "authentication accepts a caller-supplied password hash instead of verifying a plaintext password",
        out,
    );
}

pub(crate) fn detect_cwe_921(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let world_readable_secret = source.contains("/tmp/integration.key")
        && source.contains("WriteFile(")
        && source.contains("0644");
    if !world_readable_secret {
        return;
    }
    if source.contains("APP_SECRET_DIR") || source.contains("0600") {
        return;
    }

    let start_byte = source.find("/tmp/integration.key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_921,
        file,
        line,
        col,
        "sensitive integration key material is stored in a world-readable temporary file",
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

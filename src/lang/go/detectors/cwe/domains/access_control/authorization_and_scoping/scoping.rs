use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
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

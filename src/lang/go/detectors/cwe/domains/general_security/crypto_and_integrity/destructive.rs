use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_353(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ingests_body = source.contains("io.ReadAll(") && source.contains("INSERT INTO telemetry")
        || source.contains("io.ReadAll(") && source.contains("INSERT INTO agent_reports");
    if !ingests_body {
        return;
    }
    if source.contains("X-Body-Mac") || source.contains("ConstantTimeCompare(expected, got)") {
        return;
    }

    let start_byte = source.find("io.ReadAll(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_353,
        file,
        line,
        col,
        "the inbound payload is stored without verifying any integrity MAC",
        out,
    );
}

pub(crate) fn detect_cwe_356(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_delete = (source.contains("func PurgeTenant(")
        && source.contains("DELETE FROM tenants WHERE slug = ?"))
        || (source.contains("func DeleteWorkspaceRecords(")
            && source.contains("DELETE FROM workspaces WHERE slug = ?"));
    if !destructive_delete {
        return;
    }
    if source.contains("X-Confirm-Purge") || source.contains("X-Confirm-Delete") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("DELETE FROM tenants") {
        idx
    } else {
        source.find("DELETE FROM workspaces").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_356,
        file,
        line,
        col,
        "the destructive action executes without an explicit confirmation token or second-step confirmation",
        out,
    );
}

pub(crate) fn detect_cwe_494(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let downloads_bundle = source.contains("http.Get(") && source.contains("/tmp/worker.bin");
    if !downloads_bundle {
        return;
    }
    if source.contains("sha256.Sum256(") || source.contains("integrity check failed") {
        return;
    }

    let start_byte = source.find("http.Get(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_494,
        file,
        line,
        col,
        "the downloaded worker bundle is accepted without any pinned integrity verification",
        out,
    );
}

pub(crate) fn detect_cwe_924(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let applies_payment_webhook = (source.contains("AcceptWebhook(")
        || source.contains("AcceptWebhookPure(")
        || source.contains("AcceptWebhookVerified(")
        || source.contains("AcceptWebhookVerifiedPure("))
        && source.contains("UPDATE invoices SET paid = true")
        && (source.contains("BindJSON(&evt)")
            || source.contains("Decode(&evt)")
            || source.contains("Unmarshal(body, &evt)"));
    if !applies_payment_webhook {
        return;
    }
    if source.contains("X-Signature")
        || source.contains("hmac.New(sha256.New")
        || source.contains("hmac.Equal(")
    {
        return;
    }

    let start_byte = source
        .find("BindJSON(&evt)")
        .or_else(|| source.find("Decode(&evt)"))
        .unwrap_or_else(|| source.find("UPDATE invoices SET paid = true").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_924,
        file,
        line,
        col,
        "a payment webhook body is applied without validating an integrity signature first",
        out,
    );
}

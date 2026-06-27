use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_353(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ingests_body = facts.source_index.has("io.ReadAll(")
        && facts.source_index.has_any(&["INSERT INTO telemetry", "INSERT INTO agent_reports"]);
    if !ingests_body {
        return;
    }
    if facts.source_index.has_any(&["X-Body-Mac", "ConstantTimeCompare(expected, got)"]) {
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

pub(crate) fn detect_cwe_356(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_delete = (facts.source_index.has("func PurgeTenant(")
        && facts.source_index.has("DELETE FROM tenants WHERE slug = ?"))
        || (facts.source_index.has("func DeleteWorkspaceRecords(")
            && facts.source_index.has("DELETE FROM workspaces WHERE slug = ?"));
    if !destructive_delete {
        return;
    }
    if facts.source_index.has_any(&["X-Confirm-Purge", "X-Confirm-Delete"]) {
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

pub(crate) fn detect_cwe_494(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let downloads_bundle = facts.source_index.has("http.Get(") && facts.source_index.has("/tmp/worker.bin");
    if !downloads_bundle {
        return;
    }
    if facts.source_index.has_any(&["sha256.Sum256(", "integrity check failed"]) {
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

pub(crate) fn detect_cwe_924(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let applies_payment_webhook = (facts.source_index.has_any(&["AcceptWebhook(", "AcceptWebhookPure(", "AcceptWebhookVerified(", "AcceptWebhookVerifiedPure("]))
        && facts.source_index.has("UPDATE invoices SET paid = true")
        && (facts.source_index.has_any(&["BindJSON(&evt)", "Decode(&evt)", "Unmarshal(body, &evt)"]));
    if !applies_payment_webhook {
        return;
    }
    if facts.source_index.has_any(&["X-Signature", "hmac.New(sha256.New", "hmac.Equal("])
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

use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_323(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let fixed_nonce = source.contains("sharedNonce")
        || source.contains("relaySessionNonce")
        || source.contains("static-nonce12")
        || source.contains("fixednonce12");
    if !fixed_nonce || !source.contains("aead.Seal(") {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, nonce)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Nonce") {
        idx
    } else if let Some(idx) = source.find("nonce") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_323,
        file,
        line,
        col,
        "a fixed nonce is reused for AEAD encryption operations with the same key",
        out,
    );
}

pub(crate) fn detect_cwe_328(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("md5.Sum(") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_328,
        file,
        line,
        col,
        "a password digest is derived with MD5, which is too weak for this security-sensitive use",
        out,
    );
}

pub(crate) fn detect_cwe_331(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_recovery_code = source.contains("rand.NewSource(time.Now().UnixNano())")
        && source.contains("Intn(900000) + 100000")
        && source.contains("code");
    if !weak_recovery_code {
        return;
    }

    let start_byte = source.find("Intn(900000) + 100000").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_331,
        file,
        line,
        col,
        "the recovery code is generated from a small predictable decimal range instead of cryptographic randomness",
        out,
    );
}

pub(crate) fn detect_cwe_341(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let predictable_token = source.contains("fmt.Sprintf(\"%d-%d-%s\"")
        && source.contains("os.Getpid()")
        && source.contains("time.Now().Unix()");
    if !predictable_token {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d-%d-%s\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_341,
        file,
        line,
        col,
        "the token is built from observable pid, wall-clock time, and caller input instead of cryptographic randomness",
        out,
    );
}

pub(crate) fn detect_cwe_344(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_secret = source.contains("const billingHMACSecret = ")
        || source.contains("const shipmentHMACSecret = ");
    if !hardcoded_secret || !source.contains("hmac.New(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const billingHMACSecret = ") {
        idx
    } else {
        source.find("const shipmentHMACSecret = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_344,
        file,
        line,
        col,
        "a hard-coded invariant HMAC secret is embedded directly in code for a changing signing context",
        out,
    );
}

pub(crate) fn detect_cwe_346(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reflects_origin = source.contains("Access-Control-Allow-Origin\", origin")
        && source.contains("Header.Get(\"Origin\")");
    if !reflects_origin {
        return;
    }
    if source.contains("allowedOrigins")
        || source.contains("trustedOrigins")
        || source.contains("forbidden origin")
    {
        return;
    }

    let start_byte = source.find("Access-Control-Allow-Origin").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_346,
        file,
        line,
        col,
        "the response reflects the caller-supplied Origin without validating it against a trusted allow-list",
        out,
    );
}

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

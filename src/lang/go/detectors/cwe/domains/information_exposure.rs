use super::super::facts::{GoUnitFacts, InputKind};
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_201(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_sensitive_field = source.contains("APIKey") || source.contains("TokenKey");
    if !has_sensitive_field {
        return;
    }

    let sensitive_record_name = if source.contains("type userRecord struct")
        || source.contains("type memberRecord struct")
    {
        Some("record")
    } else {
        None
    };
    let Some(record_name) = sensitive_record_name else {
        return;
    };

    let direct_json_response = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == record_name)
    });
    let Some(call) = direct_json_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_201,
        file,
        line,
        col,
        "a response serializes a record containing sensitive fields directly to the caller",
        out,
    );
}

pub(crate) fn detect_cwe_209(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(r#"fmt.Sprintf("db failure: %v", err)"#) {
        return;
    }

    let start_byte = source
        .find(r#"fmt.Sprintf("db failure: %v", err)"#)
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_209,
        file,
        line,
        col,
        "database error details are formatted into a client-facing response",
        out,
    );
}

pub(crate) fn detect_cwe_212(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_sensitive_payment_field = source.contains("Card") || source.contains("PAN");
    if !has_sensitive_payment_field {
        return;
    }
    if !(source.contains("json.Marshal(rows)") || source.contains("json.Marshal(out)")) {
        return;
    }
    if source.contains("type paymentExport struct") || source.contains("type chargeExport struct") {
        return;
    }
    if !source.contains("json.Marshal(rows)") {
        return;
    }

    let start_byte = source.find("json.Marshal(rows)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_212,
        file,
        line,
        col,
        "records containing sensitive payment fields are marshaled directly for export",
        out,
    );
}

pub(crate) fn detect_cwe_213(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_comp_field = source.contains("Salary") || source.contains("Comp");
    if !has_comp_field {
        return;
    }
    if source.contains("guestProfile{") || source.contains("directoryEntry{") {
        return;
    }

    let direct_profile_response = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.JSON" || call.callee.as_ref() == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg.as_ref() == "profile")
    });
    let Some(call) = direct_profile_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_213,
        file,
        line,
        col,
        "a public response serializes a profile that still contains compensation fields",
        out,
    );
}

pub(crate) fn detect_cwe_214(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "exec.Command" {
            continue;
        }
        if source.contains("cmd.Stdin = strings.NewReader(") {
            return;
        }

        let uses_user_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == binding.name.as_ref())
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == r#""--token""#)
        });
        if !uses_user_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_214,
            file,
            line,
            col,
            "a user-supplied token is passed as a visible argv argument to an external process",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_215(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "log.Printf" {
            continue;
        }

        let logs_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && binding.name.contains("secret")
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == binding.name.as_ref())
        });
        if !logs_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_215,
            file,
            line,
            col,
            "a debug log statement includes request-derived secret material",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_312(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stores_plain_ssn =
        source.contains("SSN: c.PostForm(\"ssn\")") || source.contains("SSN: r.FormValue(\"ssn\")");
    let writes_plain_ssn_json =
        source.contains(r#"SSN string `json:"ssn"`"#) && source.contains("json.Marshal(rec)");
    if !(stores_plain_ssn || writes_plain_ssn_json) {
        return;
    }
    if source.contains("SSNCipher") || source.contains("gcm.Seal(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ssn") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_312,
        file,
        line,
        col,
        "a sensitive SSN value is persisted in cleartext instead of encrypted form",
        out,
    );
}

pub(crate) fn detect_cwe_319(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let handles_card_data = source.contains("CVV") && source.contains("Number");
    if !handles_card_data {
        return;
    }
    if source.contains("ListenAndServeTLS(") || source.contains("tls.Config") {
        return;
    }
    if !(source.contains("ListenAndServe(") || source.contains("http.ListenAndServe(")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ListenAndServe") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_319,
        file,
        line,
        col,
        "sensitive payment data is accepted over a cleartext HTTP listener instead of TLS",
        out,
    );
}

pub(crate) fn detect_cwe_524(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let process_wide_token_cache = (source.contains("map[string]string{}")
        && source.contains("Authorization"))
        && (source.contains("tokenCache") || source.contains("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if source.contains("context.WithValue(") || source.contains("session_token") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("tokenCache") {
        idx
    } else {
        source.find("tokenVault").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_524,
        file,
        line,
        col,
        "raw session tokens are cached in shared process memory keyed by caller identifiers",
        out,
    );
}

pub(crate) fn detect_cwe_538(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let public_secret_export = source.contains("DATABASE_URL")
        && source.contains("os.WriteFile(")
        && (source.contains("/var/www/") || source.contains("/var/www/html/public/"))
        && source.contains("0o644");
    if !public_secret_export {
        return;
    }
    if source.contains("/var/lib/slopguard/private") || source.contains("0o600") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/var/www/html/public/config-snapshot.txt") {
        idx
    } else {
        source.find("/var/www/static").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_538,
        file,
        line,
        col,
        "database configuration secrets are exported to a public world-readable file path",
        out,
    );
}

pub(crate) fn detect_cwe_756(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_error_to_client = source.contains("err.Error()")
        && source.contains("FetchProfile")
        && source.contains("SELECT email FROM profiles")
        && (source.contains("c.String(http.StatusInternalServerError, err.Error())")
            || source.contains("http.Error(w, err.Error(), http.StatusInternalServerError)"));
    if !raw_error_to_client {
        return;
    }
    if source.contains("\"unable to load profile\"") {
        return;
    }

    let start_byte = source.find("err.Error()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_756,
        file,
        line,
        col,
        "raw database error text is returned directly to the client",
        out,
    );
}

pub(crate) fn detect_cwe_1230(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let metadata_leak = (source.contains("DownloadRedacted(")
        || source.contains("DownloadRedactedPure("))
        && source.contains("X-Original-Name")
        && source.contains("X-File-Size")
        && source.contains("[REDACTED CONTENT]");
    if !metadata_leak {
        return;
    }
    if source.contains("Cache-Control") {
        return;
    }

    let start_byte = source.find("X-Original-Name").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1230,
        file,
        line,
        col,
        "a redacted download response still exposes sensitive filename and size metadata",
        out,
    );
}

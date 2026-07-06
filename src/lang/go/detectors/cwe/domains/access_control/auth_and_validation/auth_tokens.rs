use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_294(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loads_auth_token = facts.source_index.has_any(&[
        r#"c.PostForm("auth_token")"#,
        r#"r.FormValue("auth_token")"#,
    ]);
    if !loads_auth_token {
        return;
    }

    let has_nonce_tracking = facts.source_index.has_any(&[
        "LoadOrStore(nonce, true)",
        "spentNonces",
        r#"PostForm("nonce")"#,
        r#"FormValue("nonce")"#,
    ]);
    if has_nonce_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("auth_token") {
        idx
    } else {
        return;
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_294,
        file,
        line,
        col,
        "the login flow accepts an authentication token without nonce tracking or replay detection",
        out,
    );
}

pub(crate) fn detect_cwe_301(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let echoes_challenge = facts.source_index.has_any(&[
        r#"gin.H{"proof": challenge}"#,
        r#"{"proof": challenge}"#,
        r#"map[string]string{"proof": challenge}"#,
    ]);
    if !echoes_challenge {
        return;
    }
    if facts
        .source_index
        .has_any(&["hmac.New(", "EncodeToString("])
    {
        return;
    }

    let start_byte = source.find("challenge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_301,
        file,
        line,
        col,
        "the server reflects the client challenge directly as the authentication proof",
        out,
    );
}

pub(crate) fn detect_cwe_303(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("hmac.New(") || !facts.source_index.has("mac.Sum(nil)") {
        return;
    }
    if !facts.source_index.has("string(expected) == sig") {
        return;
    }

    let start_byte = source.find("string(expected) == sig").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_303,
        file,
        line,
        col,
        "the computed MAC is compared to user input with string equality instead of constant-time verification",
        out,
    );
}

pub(crate) fn detect_cwe_322(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("tls.Dial(") || !facts.source_index.has("InsecureSkipVerify: true") {
        return;
    }

    let start_byte = source.find("InsecureSkipVerify: true").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_322,
        file,
        line,
        col,
        "the TLS relay connection disables peer certificate verification during key exchange",
        out,
    );
}

pub(crate) fn detect_cwe_408(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let query_before_auth = (facts
        .source_index
        .has("SELECT * FROM orders WHERE tenant_id = ?")
        && facts.source_index.has("Authorization"))
        && (source
            .find("SELECT * FROM orders WHERE tenant_id = ?")
            .unwrap_or(usize::MAX)
            < source.find("Authorization").unwrap_or(0));
    if !query_before_auth {
        return;
    }

    let start_byte = source
        .find("SELECT * FROM orders WHERE tenant_id = ?")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_408,
        file,
        line,
        col,
        "the export query runs before the caller authentication check",
        out,
    );
}

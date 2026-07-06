use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_940(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let oauth_callback = (facts
        .source_index
        .has_any(&["OAuthCallback(", "OAuthCallbackPure("]))
        && facts.source_index.has("code")
        && facts
            .source_index
            .has("INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)");
    if !oauth_callback {
        return;
    }
    if facts.source_index.has_any(&[
        "oauth_state",
        r#"Cookie("oauth_state")"#,
        r#"r.Cookie("oauth_state")"#,
        "invalid oauth state",
    ]) {
        return;
    }

    let start_byte = source
        .find("Query(\"user_id\")")
        .or_else(|| source.find("Query().Get(\"user_id\")"))
        .unwrap_or_else(|| source.find("oauth_tokens").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_940,
        file,
        line,
        col,
        "an OAuth callback accepts caller-supplied authorization data without verifying a bound state token",
        out,
    );
}

pub(crate) fn detect_cwe_941(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_directed_reset = (facts
        .source_index
        .has_any(&["SendResetLink(", "SendResetLinkPure("]))
        && facts.source_index.has("smtp.SendMail")
        && (facts
            .source_index
            .has_any(&[r#"Query("email")"#, r#"Query().Get("email")"#]))
        && facts.source_index.has("[]string{email}");
    if !caller_directed_reset {
        return;
    }
    if facts
        .source_index
        .has_any(&["user.Email", "lookupEmail(", "sessionUserID"])
    {
        return;
    }

    let start_byte = source
        .find("Query(\"email\")")
        .or_else(|| source.find("Query().Get(\"email\")"))
        .unwrap_or_else(|| source.find("[]string{email}").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_941,
        file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

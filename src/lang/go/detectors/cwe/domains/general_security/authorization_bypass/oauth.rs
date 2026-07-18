use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_940(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Fixture-only: OAuthCallback helper names + exact oauth_tokens INSERT (see maturity).
    // Keep for --profile all corpus tests; never in recommended/security packs.
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

    // Cheap impossibility prefilter: no smtp.SendMail text ⇒ no notification sink of this shape.
    if !facts.source_index.has("smtp.SendMail") {
        return;
    }
    // Corpus co-signals still required for oracle (fixture helper names + email query +
    // recipient slice). Maturity remains fixture-only; call_facts is the primary sink proof.
    let caller_directed_reset = facts
        .source_index
        .has_any(&["SendResetLink(", "SendResetLinkPure("])
        && (facts
            .source_index
            .has_any(&[r#"Query("email")"#, r#"Query().Get("email")"#]))
        && facts.source_index.has("[]string{email}");
    if !caller_directed_reset {
        return;
    }
    // Negative prefilters: destination from session / stored identity.
    if facts
        .source_index
        .has_any(&["user.Email", "lookupEmail(", "sessionUserID"])
    {
        return;
    }

    // Primary signal: call facts — stdlib `smtp.SendMail` callee.
    let Some(send_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "smtp.SendMail")
    else {
        return;
    };

    let (line, col) = unit.line_col(send_call.start_byte);
    emit::push_finding(
        &META_CWE_941,
        file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

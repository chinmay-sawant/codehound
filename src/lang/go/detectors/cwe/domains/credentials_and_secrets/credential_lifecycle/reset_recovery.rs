use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_549(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let password_echo = facts.source_index.has(r#""password": pass"#)
        && (facts.source_index.has("gin.H{") || facts.source_index.has("map[string]string"));
    if !password_echo {
        return;
    }
    if facts.source_index.has(r#"Encode(map[string]string{"email": email})"#)
        || facts.source_index.has("gin.H{\n\t\t\"email\": c.PostForm(\"email\"),\n\t})")
    {
        return;
    }

    let start_byte = source.find(r#""password": pass"#).unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_549,
        file,
        line,
        col,
        "the response body reflects the submitted password back to the caller",
        out,
    );
}

pub(crate) fn detect_cwe_640(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let email_only_reset = facts.source_index.has("ForgotPassword")
        && facts.source_index.has("new_password")
        && facts.source_index.has("email")
        && (facts.source_index.has("UPDATE users SET password")
            || facts.source_index.has("Where(\"email = ?\", email).Update(\"password\", newPass)"));
    if !email_only_reset {
        return;
    }
    if facts.source_index.has("reset_tokens")
        || facts.source_index.has(r#""token""#)
        || facts.source_index.has("expires_at")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_640,
        file,
        line,
        col,
        "the recovery flow resets a password from email alone without a reset token",
        out,
    );
}

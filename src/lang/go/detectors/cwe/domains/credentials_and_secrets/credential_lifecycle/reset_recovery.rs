use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_549(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let password_echo = source.contains(r#""password": pass"#)
        && (source.contains("gin.H{") || source.contains("map[string]string"));
    if !password_echo {
        return;
    }
    if source.contains(r#"Encode(map[string]string{"email": email})"#)
        || source.contains("gin.H{\n\t\t\"email\": c.PostForm(\"email\"),\n\t})")
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

pub(crate) fn detect_cwe_640(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let email_only_reset = source.contains("ForgotPassword")
        && source.contains("new_password")
        && source.contains("email")
        && (source.contains("UPDATE users SET password")
            || source.contains("Where(\"email = ?\", email).Update(\"password\", newPass)"));
    if !email_only_reset {
        return;
    }
    if source.contains("reset_tokens")
        || source.contains(r#""token""#)
        || source.contains("expires_at")
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

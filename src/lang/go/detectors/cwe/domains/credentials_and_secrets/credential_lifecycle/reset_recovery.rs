use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Credential-lifecycle R6 trust freeze (reset_recovery.rs).
// Bounded residual family: CWE-549, CWE-640 (2 rules; whole file — ~67 lines).
// Deferred sibling from B1 / parallel-catalog-program §2.1 / issue #163;
// parent epic #151. Other credential_lifecycle leaves stay out of scope
// (credentials_in_source done B1; key_expiration / password_aging = R5).
//
// Primary evidence is SourceIndex exact corpus co-presence, not call_facts/AST.
// Response map key `"password": pass` and ForgotPassword + email-only UPDATE
// shapes are policy/museum evidence — no stronger local proof exists here.
// Proposed maturity: fixture-only for both (integrator applies maturity.rs).
// See plans/v0.0.6/evidence-r6-credential-reset-recovery.md and
// plans/v0.0.6/pr-r6-credential-reset-recovery.md.

/// CWE-549 — Missing Password Field Masking (response echo museum).
///
/// Freeze (R6 / #163): exact response map literal `"password": pass` co-present
/// with `gin.H{` or `map[string]string` (signup-preview echo). Negative gate:
/// email-only encode / gin.H email response shapes used by safe fixtures.
///
/// Neighbor, not duplicate: CWE-201 (sensitive_fields) owns APIKey/TokenKey
/// record→JSON sinks via call_facts; this rule is the password-preview echo
/// museum. Call-facts for `c.JSON` / `json.Encode` alone cannot prove password
/// reflection without the exact `"password": pass` literal. Disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_549(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): `"password": pass` + gin.H{ /
    // map[string]string response wrapper.
    // Negative gate: Encode(map…{"email": email}) / gin.H email-only response.
    let password_echo = facts.source_index.has(r#""password": pass"#)
        && (facts.source_index.has("gin.H{") || facts.source_index.has("map[string]string"));
    if !password_echo {
        return;
    }
    if facts
        .source_index
        .has(r#"Encode(map[string]string{"email": email})"#)
        || facts
            .source_index
            .has("gin.H{\n\t\t\"email\": c.PostForm(\"email\"),\n\t})")
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

/// CWE-640 — Weak Password Recovery Mechanism.
///
/// Freeze (R6 / #163): `ForgotPassword` + `new_password` + `email` plus exact
/// password UPDATE sink (`UPDATE users SET password` or GORM
/// `Where("email = ?", email).Update("password", newPass)`) without reset-token
/// co-signals (`reset_tokens` / `"token"` / `expires_at`).
///
/// Overlap vs neighbors (not duplicates):
/// - CWE-620 (`auth_flows`): ChangePassword without current_password; its
///   negative explicitly includes `ForgotPassword`, so the two museums partition
///   change-vs-recovery.
/// - CWE-941 (`oauth`): SendResetLink + smtp.SendMail email-notification museum;
///   different sink (mail) and helper names.
/// - CWE-940 (`oauth`): OAuth callback state binding; unrelated authz bypass.
///
/// Call-facts for db.Exec / GORM Update alone cannot prove email-only recovery
/// without ForgotPassword + new_password corpus co-signals (and would collide
/// with CWE-620's password-update museum). Disposition: **fixture-only**.
pub(crate) fn detect_cwe_640(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): ForgotPassword + new_password + email +
    // exact password UPDATE sink.
    // Negative gate: reset_tokens / "token" / expires_at (tokenized recovery).
    let email_only_reset = facts.source_index.has("ForgotPassword")
        && facts.source_index.has("new_password")
        && facts.source_index.has("email")
        && (facts.source_index.has("UPDATE users SET password")
            || facts
                .source_index
                .has("Where(\"email = ?\", email).Update(\"password\", newPass)"));
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

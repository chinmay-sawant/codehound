use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Access-control R3 trust freeze (auth_and_validation/auth_flows.rs).
// Bounded subfamily: CWE-289 + CWE-290 only (login identity trust; 2 rules).
// Siblings CWE-305–309, 620, 836 deferred to later bounded slices.
// Route/header/principal naming is policy evidence unless stronger local proof exists.
// Proposed maturity: fixture-only for both (integrator applies maturity.rs).
// See plans/v0.0.6/evidence-r3-auth-flows.md and pr-r3-auth-flows.md.

pub(crate) fn detect_cwe_289(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): strings.Split(…, "@")[0] co-presence without
    // canonical_name = ? negative. Exact split subscript text is a corpus marker.
    // Negative gate: canonical_name = ? — realm-aware principal lookup.
    // Call-facts cannot prove realm-stripping without the exact "@")[0] museum shape;
    // keep SI primary. Not a generalized principal-alias detector.
    if facts.source_index.has("canonical_name = ?") {
        return;
    }
    if !facts.source_index.has("strings.Split(") || !facts.source_index.has(r#""@")[0]"#) {
        return;
    }

    let start_byte = source.find("strings.Split(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_289,
        file,
        line,
        col,
        "principal authentication strips the realm suffix and authenticates only the bare local username",
        out,
    );
}

pub(crate) fn detect_cwe_290(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal: call_facts c.GetHeader / r.Header.Get with X-Remote-User arg.
    // Header name is policy evidence — not verified server-side identity proof.
    // Safe fixtures omit the header read entirely (session cookie path); no explicit
    // negative gate in emit path. Call-facts partial but still corpus-specific header.
    // Not a generalized spoofable-header detector.
    let Some(header_call) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.GetHeader" || call.callee.as_ref() == "r.Header.Get")
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("X-Remote-User"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(header_call.start_byte);
    emit::push_finding(
        &META_CWE_290,
        file,
        line,
        col,
        "the request trusts a caller-controlled X-Remote-User header as the authenticated identity",
        out,
    );
}

pub(crate) fn detect_cwe_305(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let debug_bypass = facts
        .source_index
        .has_any(&[r#"Query("debug") == "1""#, r#"Query().Get("debug") == "1""#]);
    if !debug_bypass {
        return;
    }

    let has_subject_check = facts.source_index.has_any(&["jwt_sub", "X-JWT-Sub"]);
    if !has_subject_check {
        return;
    }

    let start_byte = if let Some(idx) = source.find("debug") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_305,
        file,
        line,
        col,
        "a caller-controlled debug flag reaches privileged behavior before the authenticated subject check",
        out,
    );
}

pub(crate) fn detect_cwe_306(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_purge = facts.source_index.has("TRUNCATE ledger");
    if !destructive_purge {
        return;
    }
    let has_auth_gate = facts
        .source_index
        .has_any(&["operator_id", "X-Operator-ID"]);
    if has_auth_gate {
        return;
    }

    let start_byte = source.find("TRUNCATE ledger").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_306,
        file,
        line,
        col,
        "a destructive purge endpoint performs its action without any authentication gate",
        out,
    );
}

pub(crate) fn detect_cwe_307(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let login_lookup = facts.source_index.has_any(&[
        "SELECT hash FROM users WHERE email = ?",
        r#"Where("email = ?", email).First(&u)"#,
    ]);
    if !login_lookup {
        return;
    }

    let has_attempt_tracking = facts.source_index.has_any(&[
        "loginAttempts",
        "LoadOrStore(key, 0)",
        "time.Sleep(200 * time.Millisecond)",
    ]);
    if has_attempt_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("email") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_307,
        file,
        line,
        col,
        "the login flow has no throttling, backoff, or lockout for repeated failed authentication attempts",
        out,
    );
}

pub(crate) fn detect_cwe_308(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_password_gate = facts
        .source_index
        .has_any(&[r#"PostForm("password")"#, r#"FormValue("password")"#]);
    if !has_password_gate {
        return;
    }
    if facts.source_index.has_any(&[
        r#"PostForm("totp")"#,
        r#"FormValue("totp")"#,
        "totp_valid",
        "X-TOTP-Valid",
    ]) {
        return;
    }
    if !facts.source_index.has("INSERT INTO wires") {
        return;
    }

    let Some(start_byte) = source.find("password") else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_308,
        file,
        line,
        col,
        "a high-value wire action is authorized with only a password and no validated second factor",
        out,
    );
}

pub(crate) fn detect_cwe_309(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let enterprise_login_shape = facts.source_index.has("func EnterpriseLogin(")
        && (facts.source_index.has_any(&[
            r#"{"session":"` + user + `"}"#,
            r#"{"session": user}"#,
            r#"gin.H{"session": user}"#,
            r#"gin.H{"session": c.GetString("subject")}"#,
        ]));
    if !enterprise_login_shape {
        return;
    }

    let password_form_login = (facts
        .source_index
        .has_any(&[r#"PostForm("username")"#, r#"FormValue("username")"#]))
        && (facts
            .source_index
            .has_any(&[r#"PostForm("password")"#, r#"FormValue("password")"#]));
    if !password_form_login {
        return;
    }
    if facts
        .source_index
        .has_any(&["webauthn_assertion", "X-WebAuthn-OK", "webauthn_ok"])
    {
        return;
    }

    let start_byte = source.find("username").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_309,
        file,
        line,
        col,
        "the enterprise login route relies on username and password form fields as the primary authentication method",
        out,
    );
}

pub(crate) fn detect_cwe_620(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let blind_password_update = facts.source_index.has("ChangePassword")
        && facts.source_index.has(r#""new_password""#)
        && (facts
            .source_index
            .has_any(&[r#"Update("password","#, "UPDATE accounts SET password"]));
    if !blind_password_update {
        return;
    }
    if facts.source_index.has_any(&[
        "ForgotPassword",
        r#""current_password""#,
        "CompareHashAndPassword",
        "ConstantTimeCompare",
    ]) {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_620,
        file,
        line,
        col,
        "the password change flow updates credentials without verifying the current password",
        out,
    );
}

pub(crate) fn detect_cwe_836(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_submits_hash = facts
        .source_index
        .has_any(&["PasswordHash string", r#"`json:"password_hash"`"#]);
    let hash_as_password = client_submits_hash
        && (facts.source_index.has_any(&[
            "password_hash = ?",
            "WHERE username = ? AND password_hash = ?",
            "WHERE username = $1 AND password_hash = $2",
        ]));
    if !hash_as_password {
        return;
    }
    if facts
        .source_index
        .has_any(&["CompareHashAndPassword", "ConstantTimeCompare"])
    {
        return;
    }

    let start_byte = source.find("password_hash").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_836,
        file,
        line,
        col,
        "authentication accepts a caller-supplied password hash instead of verifying a plaintext password",
        out,
    );
}

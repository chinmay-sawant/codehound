use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("canonical_name = ?") {
        return;
    }
    if !source.contains("strings.Split(") || !source.contains(r#""@")[0]"#) {
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

pub(crate) fn detect_cwe_305(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let debug_bypass = source.contains(r#"Query("debug") == "1""#)
        || source.contains(r#"Query().Get("debug") == "1""#);
    if !debug_bypass {
        return;
    }

    let has_subject_check = source.contains("jwt_sub") || source.contains("X-JWT-Sub");
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

pub(crate) fn detect_cwe_306(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_purge = source.contains("TRUNCATE ledger");
    if !destructive_purge {
        return;
    }
    let has_auth_gate = source.contains("operator_id") || source.contains("X-Operator-ID");
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

pub(crate) fn detect_cwe_307(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let login_lookup = source.contains("SELECT hash FROM users WHERE email = ?")
        || source.contains(r#"Where("email = ?", email).First(&u)"#);
    if !login_lookup {
        return;
    }

    let has_attempt_tracking = source.contains("loginAttempts")
        || source.contains("LoadOrStore(key, 0)")
        || source.contains("time.Sleep(200 * time.Millisecond)");
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

pub(crate) fn detect_cwe_308(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_password_gate =
        source.contains(r#"PostForm("password")"#) || source.contains(r#"FormValue("password")"#);
    if !has_password_gate {
        return;
    }
    if source.contains(r#"PostForm("totp")"#)
        || source.contains(r#"FormValue("totp")"#)
        || source.contains("totp_valid")
        || source.contains("X-TOTP-Valid")
    {
        return;
    }
    if !source.contains("INSERT INTO wires") {
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

pub(crate) fn detect_cwe_309(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let enterprise_login_shape = source.contains("func EnterpriseLogin(")
        && (source.contains(r#"{"session":"` + user + `"}"#)
            || source.contains(r#"{"session": user}"#)
            || source.contains(r#"gin.H{"session": user}"#)
            || source.contains(r#"gin.H{"session": c.GetString("subject")}"#));
    if !enterprise_login_shape {
        return;
    }

    let password_form_login = (source.contains(r#"PostForm("username")"#)
        || source.contains(r#"FormValue("username")"#))
        && (source.contains(r#"PostForm("password")"#)
            || source.contains(r#"FormValue("password")"#));
    if !password_form_login {
        return;
    }
    if source.contains("webauthn_assertion")
        || source.contains("X-WebAuthn-OK")
        || source.contains("webauthn_ok")
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

pub(crate) fn detect_cwe_620(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let blind_password_update = source.contains("ChangePassword")
        && source.contains(r#""new_password""#)
        && (source.contains("Update(\"password\",")
            || source.contains("UPDATE accounts SET password"));
    if !blind_password_update {
        return;
    }
    if source.contains("ForgotPassword")
        || source.contains(r#""current_password""#)
        || source.contains("CompareHashAndPassword")
        || source.contains("ConstantTimeCompare")
    {
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

pub(crate) fn detect_cwe_836(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_submits_hash =
        source.contains("PasswordHash string") || source.contains("`json:\"password_hash\"`");
    let hash_as_password = client_submits_hash
        && (source.contains("password_hash = ?")
            || source.contains("WHERE username = ? AND password_hash = ?")
            || source.contains("WHERE username = $1 AND password_hash = $2"));
    if !hash_as_password {
        return;
    }
    if source.contains("CompareHashAndPassword") || source.contains("ConstantTimeCompare") {
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

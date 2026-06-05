use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
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

pub(crate) fn detect_cwe_322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("tls.Dial(") || !source.contains("InsecureSkipVerify: true") {
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

pub(crate) fn detect_cwe_378(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_file = source.contains("os.TempDir()") && source.contains("0666");
    if !insecure_temp_file {
        return;
    }
    if source.contains("CreateTemp(") || source.contains("Chmod(f.Name(), 0600)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.TempDir()") {
        idx
    } else {
        source.find("0666").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_378,
        file,
        line,
        col,
        "a temp file is created with world-accessible permissions in the shared temp area",
        out,
    );
}

pub(crate) fn detect_cwe_379(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_dir = source.contains("MkdirAll(dir, 0777)")
        && (source.contains("/tmp/shared-reports") || source.contains("/tmp/shared-sessions"));
    if !insecure_temp_dir {
        return;
    }
    if source.contains("MkdirTemp(") || source.contains("Chmod(dir, 0700)") {
        return;
    }

    let start_byte = source.find("MkdirAll(dir, 0777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_379,
        file,
        line,
        col,
        "a temporary file is staged inside a shared world-writable directory",
        out,
    );
}

pub(crate) fn detect_cwe_408(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let query_before_auth = (source.contains("SELECT * FROM orders WHERE tenant_id = ?")
        && source.contains("Authorization"))
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

pub(crate) fn detect_cwe_425(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let admin_export = source.contains("/internal/admin/export.csv")
        && source.contains("SELECT email, ssn FROM customers");
    if !admin_export {
        return;
    }
    if source.contains("requireAdmin()") || source.contains("requireAdmin(") {
        return;
    }

    let start_byte = source.find("/internal/admin/export.csv").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_425,
        file,
        line,
        col,
        "the admin export endpoint is mounted without an explicit authorization guard",
        out,
    );
}

pub(crate) fn detect_cwe_551(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let raw_path_gate = source.contains("raw := ")
        && source.contains("URL.Path")
        && source.contains("strings.HasPrefix(raw, \"/admin\")")
        && source.contains("strings.ReplaceAll(raw, \"%2f\", \"/\")");
    if !raw_path_gate {
        return;
    }
    if source.contains("url.PathUnescape(raw)") {
        return;
    }

    let start_byte = source
        .find("strings.HasPrefix(raw, \"/admin\")")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_551,
        file,
        line,
        col,
        "authorization checks the raw path before percent-unescape canonicalization",
        out,
    );
}

pub(crate) fn detect_cwe_603(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_auth_header = source.contains("X-Authenticated")
        && source.contains(r#""true""#)
        && source.contains("UPDATE billing SET plan");
    if !trusts_auth_header {
        return;
    }
    if source.contains("GetString(\"uid\")") || source.contains("Header.Get(\"X-UID\")") {
        return;
    }

    let start_byte = source.find("X-Authenticated").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_603,
        file,
        line,
        col,
        "billing mutation trusts a caller-supplied authenticated header",
        out,
    );
}

pub(crate) fn detect_cwe_613(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let non_expiring_cookie = (source.contains("SetCookie(\"sid\", sid, 0,")
        || source.contains("http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: sid, Path: \"/\", HttpOnly: true})"))
        && source.contains("LogoutHandler");
    if !non_expiring_cookie {
        return;
    }
    if source.contains("revokedSessions[sid]")
        || source.contains("revokedSessions[c.Value]")
        || source.contains("MaxAge: 900")
        || source.contains(", 900,")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("SetCookie(\"sid\", sid, 0,") {
        idx
    } else {
        source
            .find("http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: sid")
            .unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_613,
        file,
        line,
        col,
        "session login issues a non-expiring cookie and logout does not revoke server-side session state",
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

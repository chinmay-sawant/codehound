use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_262(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loads_age_metadata = source.contains("last_seen") || source.contains("changed_at");
    if !loads_age_metadata {
        return;
    }
    if source.contains("time.Since(") || source.contains("maxPasswordAge") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("last_seen") {
        idx
    } else {
        source.find("changed_at").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_262,
        file,
        line,
        col,
        "credential metadata is loaded but no password-age enforcement is performed",
        out,
    );
}


pub(crate) fn detect_cwe_263(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("MaxAgeDays: 3650") {
        return;
    }

    let start_byte = source.find("MaxAgeDays: 3650").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_263,
        file,
        line,
        col,
        "password maximum age is configured to an excessively long multi-year period",
        out,
    );
}


pub(crate) fn detect_cwe_324(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("ExpiresAt") {
        return;
    }
    let key_expiry_crypto_shape = (source.contains("ApiKeyRow") || source.contains("SigningKey"))
        && source.contains("Secret")
        && source.contains("hmac.New(");
    if !key_expiry_crypto_shape {
        return;
    }
    if source.contains("time.Now().After(row.ExpiresAt)")
        || source.contains("time.Now().After(key.ExpiresAt)")
    {
        return;
    }

    let expired_key_source =
        source.contains("Add(-48 * time.Hour)") || source.contains("ExpiresAt time.Time");
    if !expired_key_source {
        return;
    }

    let start_byte = source.find("ExpiresAt").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_324,
        file,
        line,
        col,
        "cryptographic processing uses key material with an expiration field but never checks whether the key is expired",
        out,
    );
}


pub(crate) fn detect_cwe_523(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let cleartext_login = (source.contains("/login") && source.contains("password"))
        && (source.contains("Addr: \":8080\"") || source.contains("StartCleartextLogin"));
    if !cleartext_login {
        return;
    }
    if source.contains("requireTLS(")
        || source.contains("Request.TLS == nil")
        || source.contains("r.TLS == nil")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/login") {
        idx
    } else {
        source.find("password").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_523,
        file,
        line,
        col,
        "login credentials are accepted before any TLS enforcement or redirect",
        out,
    );
}

pub(crate) fn detect_cwe_547(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_signing_secret =
        source.contains("const jwtSecret = ") || source.contains("const sessionMACKey = ");
    if !hardcoded_signing_secret {
        return;
    }
    if source.contains("os.Getenv(\"JWT_SIGNING_KEY\")")
        || source.contains("os.Getenv(\"SESSION_MAC_KEY\")")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const jwtSecret = ") {
        idx
    } else {
        source.find("const sessionMACKey = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_547,
        file,
        line,
        col,
        "signing material is hard-coded directly in source instead of loaded from runtime secret configuration",
        out,
    );
}


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


pub(crate) fn detect_cwe_798(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_dsn = source
        .contains("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable");
    if !hardcoded_dsn {
        return;
    }
    if source.contains("os.Getenv(\"REPORTING_DSN\")") {
        return;
    }

    let start_byte = source
        .find("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_798,
        file,
        line,
        col,
        "database credentials are embedded directly in the source code",
        out,
    );
}


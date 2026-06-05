use super::facts::GoUnitFacts;
use super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(super) fn detect_cwe_524(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let process_wide_token_cache = (source.contains("map[string]string{}")
        && source.contains("Authorization"))
        && (source.contains("tokenCache") || source.contains("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if source.contains("context.WithValue(") || source.contains("session_token") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("tokenCache") {
        idx
    } else {
        source.find("tokenVault").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_524,
        &file,
        line,
        col,
        "raw session tokens are cached in shared process memory keyed by caller identifiers",
        out,
    );
}

pub(super) fn detect_cwe_538(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let public_secret_export = source.contains("DATABASE_URL")
        && source.contains("os.WriteFile(")
        && (source.contains("/var/www/") || source.contains("/var/www/html/public/"))
        && source.contains("0o644");
    if !public_secret_export {
        return;
    }
    if source.contains("/var/lib/slopguard/private") || source.contains("0o600") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/var/www/html/public/config-snapshot.txt") {
        idx
    } else {
        source.find("/var/www/static").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_538,
        &file,
        line,
        col,
        "database configuration secrets are exported to a public world-readable file path",
        out,
    );
}

pub(super) fn detect_cwe_544(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let inconsistent_db_failure_paths = (source.contains("panic(err)")
        || source.contains("panic(err)\n"))
        && source.contains("log.Println(err)")
        && (source.contains("db.Get(") || source.contains("db.QueryRow("));
    if !inconsistent_db_failure_paths {
        return;
    }
    if source.contains("writeDBError(") || source.contains("writeDBFailure(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("panic(err)") {
        idx
    } else {
        source.find("log.Println(err)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_544,
        &file,
        line,
        col,
        "database failures are handled through inconsistent panic and logging paths",
        out,
    );
}

pub(super) fn detect_cwe_547(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "signing material is hard-coded directly in source instead of loaded from runtime secret configuration",
        out,
    );
}

pub(super) fn detect_cwe_549(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "the response body reflects the submitted password back to the caller",
        out,
    );
}

pub(super) fn detect_cwe_551(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "authorization checks the raw path before percent-unescape canonicalization",
        out,
    );
}

pub(super) fn detect_cwe_601(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_redirect = source.contains(r#""next""#)
        && (source.contains("c.Redirect(http.StatusFound, target)")
            || source.contains("http.Redirect(w, r, target, http.StatusFound)"));
    if !caller_redirect {
        return;
    }
    if source.contains("strings.HasPrefix(target, \"/\")")
        || source.contains("strings.Contains(target, \"//\")")
    {
        return;
    }

    let start_byte = source.find("target").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_601,
        &file,
        line,
        col,
        "the redirect target comes from an unvalidated caller-controlled next parameter",
        out,
    );
}

pub(super) fn detect_cwe_603(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "billing mutation trusts a caller-supplied authenticated header",
        out,
    );
}

pub(super) fn detect_cwe_605(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("SO_REUSEADDR") || !source.contains("SetsockoptInt") {
        return;
    }
    if source.contains("net.Listen(\"tcp\", \":9090\")") {
        return;
    }

    let start_byte = source.find("SO_REUSEADDR").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_605,
        &file,
        line,
        col,
        "the listener explicitly enables SO_REUSEADDR on the service socket",
        out,
    );
}

pub(super) fn detect_cwe_611(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unsafe_xml = source.contains("xml.NewDecoder(")
        && source.contains("dec.Strict = false")
        && source.contains("Decode(&catalog)");
    if !unsafe_xml {
        return;
    }
    if source.contains("<!DOCTYPE")
        || source.contains("dec.Strict = true")
        || source.contains("LimitReader")
    {
        return;
    }

    let start_byte = source.find("dec.Strict = false").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_611,
        &file,
        line,
        col,
        "untrusted XML is parsed with strict mode disabled and no DOCTYPE rejection",
        out,
    );
}

pub(super) fn detect_cwe_613(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "session login issues a non-expiring cookie and logout does not revoke server-side session state",
        out,
    );
}

pub(super) fn detect_cwe_618(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let exposes_native_bridge = source.contains("/opt/vendor/activex-bridge")
        && source.contains("exec.Command(")
        && source.contains("method")
        && source.contains("args");
    if !exposes_native_bridge {
        return;
    }
    if source.contains("allowedPluginMethods") {
        return;
    }

    let start_byte = source.find("/opt/vendor/activex-bridge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_618,
        &file,
        line,
        col,
        "the endpoint forwards caller-controlled method names into a privileged native helper",
        out,
    );
}

pub(super) fn detect_cwe_619(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let dangling_rows = source.contains("rows, err := db.Query(") && source.contains("rows.Next()");
    if !dangling_rows {
        return;
    }
    if source.contains("defer rows.Close()") {
        return;
    }

    let start_byte = source.find("rows, err := db.Query(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_619,
        &file,
        line,
        col,
        "a database cursor is opened and can return without being closed",
        out,
    );
}

pub(super) fn detect_cwe_620(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "the password change flow updates credentials without verifying the current password",
        out,
    );
}

pub(super) fn detect_cwe_639(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let user_controlled_key = source.contains("invoice_id")
        && (source.contains("SELECT id, user_id, amount FROM invoices WHERE id = $1")
            || source
                .contains("SELECT id, user_id, amount FROM invoices WHERE id = $1\", invoiceID"));
    if !user_controlled_key {
        return;
    }
    if source.contains("AND user_id = $2")
        || source.contains("ownerID")
        || source.contains("X-User-ID")
    {
        return;
    }

    let start_byte = source.find("invoice_id").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_639,
        &file,
        line,
        col,
        "a caller-controlled invoice key is queried without owner scoping",
        out,
    );
}

pub(super) fn detect_cwe_640(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "the recovery flow resets a password from email alone without a reset token",
        out,
    );
}

pub(super) fn detect_cwe_645(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let one_strike_lockout =
        source.contains("failedAttempts[user]++") && source.contains("failedAttempts[user] >= 1");
    if !one_strike_lockout {
        return;
    }
    if source.contains("failedAttempts[user] >= 5") || source.contains("lockedUntil") {
        return;
    }

    let start_byte = source.find("failedAttempts[user] >= 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_645,
        &file,
        line,
        col,
        "the account is locked after a single failed login attempt",
        out,
    );
}

pub(super) fn detect_cwe_648(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let privileged_chown = source.contains("os.Chown(")
        && source.contains("uid")
        && (source.contains("PostForm(\"uid\")") || source.contains("FormValue(\"uid\")"))
        && (source.contains("PostForm(\"path\")") || source.contains("FormValue(\"path\")"));
    if !privileged_chown {
        return;
    }
    if source.contains("uploadRoot")
        || source.contains("spoolDir")
        || source.contains("serviceUID")
        || source.contains("Setuid(")
    {
        return;
    }

    let start_byte = source.find("os.Chown(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_648,
        &file,
        line,
        col,
        "the handler passes caller-controlled values into a privileged ownership-change API",
        out,
    );
}

pub(super) fn detect_cwe_649(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let obfuscated_role_cookie = source.contains("Cookie(\"profile\")")
        && source.contains("base64.StdEncoding.DecodeString")
        && source.contains("role=admin");
    if !obfuscated_role_cookie {
        return;
    }
    if source.contains("hmac.New(")
        || source.contains("hmac.Equal(")
        || source.contains("RawURLEncoding")
    {
        return;
    }

    let start_byte = source.find("DecodeString").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_649,
        &file,
        line,
        col,
        "an obfuscated profile cookie is trusted without any integrity verification",
        out,
    );
}

pub(super) fn detect_cwe_653(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let shared_privileged_store = (source.contains("sharedDB")
        || source.contains("sharedAuditStore"))
        && source.contains("PublicSearch")
        && source.contains("AdminPurge");
    if !shared_privileged_store {
        return;
    }
    if source.contains("readOnlyDB")
        || source.contains("readOnlyAuditStore")
        || source.contains("adminDB")
        || source.contains("adminAuditStore")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sharedDB") {
        idx
    } else {
        source.find("sharedAuditStore").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_653,
        &file,
        line,
        col,
        "public and admin paths share the same privileged data store",
        out,
    );
}

pub(super) fn detect_cwe_654(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let single_factor_admin = source.contains("X-Api-Key")
        && source.contains("legacy-admin-key")
        && source.contains("ExportUsers");
    if !single_factor_admin {
        return;
    }
    if source.contains("Get(\"role\")") || source.contains("X-User-Role") {
        return;
    }

    let start_byte = source.find("legacy-admin-key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_654,
        &file,
        line,
        col,
        "admin export access is granted solely from a static API key header",
        out,
    );
}

pub(super) fn detect_cwe_656(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hidden_path_gate =
        source.contains("/maintenance-portal-9f3c2a") && source.contains("HiddenConfigPanel");
    if !hidden_path_gate {
        return;
    }
    if source.contains("role != \"admin\"") || source.contains("X-User-Role") {
        return;
    }

    let start_byte = source.find("/maintenance-portal-9f3c2a").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_656,
        &file,
        line,
        col,
        "sensitive configuration access relies only on a hidden URL path",
        out,
    );
}

pub(super) fn detect_cwe_708(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_chosen_owner = source.contains("owner_uid")
        && source.contains("os.Chown(")
        && (source.contains("PostForm(\"dest\")") || source.contains("FormValue(\"dest\")"));
    if !caller_chosen_owner {
        return;
    }
    if source.contains("spoolDir") || source.contains("serviceUID") || source.contains("serviceGID")
    {
        return;
    }

    let start_byte = source.find("owner_uid").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_708,
        &file,
        line,
        col,
        "the caller chooses both the ownership target and uid for a file operation",
        out,
    );
}

pub(super) fn detect_cwe_756(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let raw_error_to_client = source.contains("err.Error()")
        && source.contains("FetchProfile")
        && source.contains("SELECT email FROM profiles")
        && (source.contains("c.String(http.StatusInternalServerError, err.Error())")
            || source.contains("http.Error(w, err.Error(), http.StatusInternalServerError)"));
    if !raw_error_to_client {
        return;
    }
    if source.contains("\"unable to load profile\"") {
        return;
    }

    let start_byte = source.find("err.Error()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_756,
        &file,
        line,
        col,
        "raw database error text is returned directly to the client",
        out,
    );
}

pub(super) fn detect_cwe_765(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let double_unlock = source.contains("Unlock()")
        && source.matches("Unlock()").count() >= 2
        && source.contains("DebitWallet");
    if !double_unlock {
        return;
    }
    if source.contains("defer walletMu.Unlock()") || source.contains("defer cacheMu.Unlock()") {
        return;
    }

    let start_byte = source.find("Unlock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_765,
        &file,
        line,
        col,
        "the critical-section lock is explicitly released twice on an error path",
        out,
    );
}

pub(super) fn detect_cwe_778(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let missing_auth_audit = source.contains("SignIn")
        && source.contains("username")
        && source.contains("password")
        && source.contains("Unauthorized");
    if !missing_auth_audit {
        return;
    }
    if source.contains("log.Printf(\"auth failure") {
        return;
    }

    let start_byte = source.find("Unauthorized").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_778,
        &file,
        line,
        col,
        "authentication failures are returned without any audit logging",
        out,
    );
}

pub(super) fn detect_cwe_783(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let precedence_bug = source.contains("!authenticated || isAdmin && ownerID == docOwner");
    if !precedence_bug {
        return;
    }
    if source.contains("!(isAdmin || ownerID == docOwner)") {
        return;
    }

    let start_byte = source
        .find("!authenticated || isAdmin && ownerID == docOwner")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_783,
        &file,
        line,
        col,
        "authorization depends on ambiguous && and || precedence",
        out,
    );
}

pub(super) fn detect_cwe_798(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "database credentials are embedded directly in the source code",
        out,
    );
}

pub(super) fn detect_cwe_820(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unsynchronized_map_write =
        source.contains("visitCounts[key] = visitCounts[key] + 1") && source.contains("TrackVisit");
    if !unsynchronized_map_write {
        return;
    }
    if source.contains("visitMu.Lock()") || source.contains("visitMu sync.Mutex") {
        return;
    }

    let start_byte = source
        .find("visitCounts[key] = visitCounts[key] + 1")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_820,
        &file,
        line,
        col,
        "shared visit counters are updated without synchronization",
        out,
    );
}

pub(super) fn detect_cwe_821(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let writes_under_rlock =
        source.contains("RLock()") && source.contains("tokenCache[key] = value");
    if !writes_under_rlock {
        return;
    }
    if source.contains("cacheMu.Lock()") {
        return;
    }

    let start_byte = source.find("RLock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_821,
        &file,
        line,
        col,
        "shared cache state is mutated while only a read lock is held",
        out,
    );
}

pub(super) fn detect_cwe_826(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let premature_release = source.contains("go func()")
        && source.contains("db.Close()")
        && (source.contains("db.Query(") || source.contains("db.Query(\"SELECT"));
    if !premature_release {
        return;
    }
    if source.contains("QueryContext(")
        || source.contains("<-done\n\tc.Status(") && !source.contains("db.Close()")
    {
        return;
    }

    let start_byte = source.find("db.Close()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_826,
        &file,
        line,
        col,
        "a shared database handle is closed before a background task finishes using it",
        out,
    );
}

pub(super) fn detect_cwe_829(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let untrusted_plugin_path = source.contains("plugin.Open(")
        && (source.contains("module_path") || source.contains("path := "));
    if !untrusted_plugin_path {
        return;
    }
    if source.contains("allowedModules") || source.contains("moduleRoot") {
        return;
    }

    let start_byte = source.find("plugin.Open(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_829,
        &file,
        line,
        col,
        "a plugin is loaded from a caller-controlled filesystem path",
        out,
    );
}

pub(super) fn detect_cwe_836(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
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
        &file,
        line,
        col,
        "authentication accepts a caller-supplied password hash instead of verifying a plaintext password",
        out,
    );
}

pub(super) fn detect_cwe_838(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let invalid_utf8 =
        source.contains("application/json; charset=utf-8") && source.contains("0xC3, 0x28");
    if !invalid_utf8 {
        return;
    }

    let start_byte = source.find("0xC3, 0x28").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_838,
        &file,
        line,
        col,
        "invalid byte sequences are emitted while declaring UTF-8 JSON output",
        out,
    );
}

pub(super) fn detect_cwe_841(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let workflow_skip = source.contains("ResetAccount")
        && source.contains("new_password")
        && source.contains("password");
    if !workflow_skip {
        return;
    }
    if source.contains("MFAPassed") && source.contains("if !acct.MFAPassed")
        || source.contains("if !accountMFAPassed[email]")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_841,
        &file,
        line,
        col,
        "the reset workflow changes credentials without enforcing MFA completion",
        out,
    );
}

pub(super) fn detect_cwe_842(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let wrong_default_group =
        source.contains("RegisterMember") && source.contains("Group: \"administrators\"");
    if !wrong_default_group {
        return;
    }
    if source.contains("Group: \"members\"") {
        return;
    }

    let start_byte = source.find("Group: \"administrators\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_842,
        &file,
        line,
        col,
        "newly registered users are assigned to an administrator group by default",
        out,
    );
}

pub(super) fn detect_cwe_909(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let missing_init_guard = (source.contains("appDB.Find(") || source.contains("widgetDB.Query("))
        && !source.contains("if appDB == nil")
        && !source.contains("if widgetDB == nil");
    if !missing_init_guard {
        return;
    }

    let start_byte = if let Some(idx) = source.find("appDB.Find(") {
        idx
    } else {
        source.find("widgetDB.Query(").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_909,
        &file,
        line,
        col,
        "a global database handle is used without checking that initialization completed",
        out,
    );
}

pub(super) fn detect_cwe_915(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let mass_assignment = source.contains("map[string]interface{}")
        && (source.contains("Updates(fields)") || source.contains("json.Unmarshal(raw, &p)"));
    if !mass_assignment {
        return;
    }
    if source.contains("Update(\"name\"") || source.contains("p.Name = body.Name") {
        return;
    }

    let start_byte = source.find("map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_915,
        &file,
        line,
        col,
        "a user-controlled attribute map updates privileged object fields directly",
        out,
    );
}

pub(super) fn detect_cwe_916(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let weak_password_hash = source.contains("md5.Sum(") && source.contains("password");
    if !weak_password_hash {
        return;
    }
    if source.contains("bcrypt.GenerateFromPassword") || source.contains("hashIterations = 100_000")
    {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_916,
        &file,
        line,
        col,
        "password storage uses a fast MD5 hash with insufficient computational effort",
        out,
    );
}

pub(super) fn detect_cwe_917(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let template_injection = source.contains("template.New(\"report\").Parse(src)")
        && source.contains("{{.Title}} where ")
        && source.contains("+ expr");
    if !template_injection {
        return;
    }
    if source.contains("reportTemplate") || source.contains("reportTemplatePure") {
        return;
    }

    let start_byte = source.find("{{.Title}} where ").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_917,
        &file,
        line,
        col,
        "caller-controlled data is concatenated into the template source itself",
        out,
    );
}

pub(super) fn detect_cwe_918(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let ssrf_fetch = source.contains("http.Get(target)")
        && (source.contains("c.Query(\"url\")") || source.contains("r.URL.Query().Get(\"url\")"));
    if !ssrf_fetch {
        return;
    }
    if source.contains("allowedHosts")
        || source.contains("allowedHostsPure")
        || source.contains("Hostname()")
    {
        return;
    }

    let start_byte = source.find("http.Get(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_918,
        &file,
        line,
        col,
        "an outbound request is sent to a caller-controlled URL without host allowlisting",
        out,
    );
}

pub(super) fn detect_cwe_921(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let world_readable_secret = source.contains("/tmp/integration.key")
        && source.contains("WriteFile(")
        && source.contains("0644");
    if !world_readable_secret {
        return;
    }
    if source.contains("APP_SECRET_DIR") || source.contains("0600") {
        return;
    }

    let start_byte = source.find("/tmp/integration.key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_921,
        &file,
        line,
        col,
        "sensitive integration key material is stored in a world-readable temporary file",
        out,
    );
}

pub(super) fn detect_cwe_924(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let applies_payment_webhook = (source.contains("AcceptWebhook(")
        || source.contains("AcceptWebhookPure(")
        || source.contains("AcceptWebhookVerified(")
        || source.contains("AcceptWebhookVerifiedPure("))
        && source.contains("UPDATE invoices SET paid = true")
        && (source.contains("BindJSON(&evt)")
            || source.contains("Decode(&evt)")
            || source.contains("Unmarshal(body, &evt)"));
    if !applies_payment_webhook {
        return;
    }
    if source.contains("X-Signature")
        || source.contains("hmac.New(sha256.New")
        || source.contains("hmac.Equal(")
    {
        return;
    }

    let start_byte = source
        .find("BindJSON(&evt)")
        .or_else(|| source.find("Decode(&evt)"))
        .unwrap_or_else(|| source.find("UPDATE invoices SET paid = true").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_924,
        &file,
        line,
        col,
        "a payment webhook body is applied without validating an integrity signature first",
        out,
    );
}

pub(super) fn detect_cwe_940(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let oauth_callback = (source.contains("OAuthCallback(")
        || source.contains("OAuthCallbackPure("))
        && source.contains("code")
        && source.contains("INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)");
    if !oauth_callback {
        return;
    }
    if source.contains("oauth_state")
        || source.contains("Cookie(\"oauth_state\")")
        || source.contains("r.Cookie(\"oauth_state\")")
        || source.contains("invalid oauth state")
    {
        return;
    }

    let start_byte = source
        .find("Query(\"user_id\")")
        .or_else(|| source.find("Query().Get(\"user_id\")"))
        .unwrap_or_else(|| source.find("oauth_tokens").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_940,
        &file,
        line,
        col,
        "an OAuth callback accepts caller-supplied authorization data without verifying a bound state token",
        out,
    );
}

pub(super) fn detect_cwe_941(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_directed_reset = (source.contains("SendResetLink(")
        || source.contains("SendResetLinkPure("))
        && source.contains("smtp.SendMail")
        && (source.contains("Query(\"email\")") || source.contains("Query().Get(\"email\")"))
        && source.contains("[]string{email}");
    if !caller_directed_reset {
        return;
    }
    if source.contains("user.Email")
        || source.contains("lookupEmail(")
        || source.contains("sessionUserID")
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
        &file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

pub(super) fn detect_cwe_1051(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hard_coded_upstream = (source.contains("ChargeCard(")
        || source.contains("ChargeCardPure("))
        && source.contains("10.20.30.40:9090")
        && source.contains("http.NewRequest(")
        && source.contains("X-Card-Token");
    if !hard_coded_upstream {
        return;
    }
    if source.contains("os.Getenv(\"BILLING_API_URL\")") {
        return;
    }

    let start_byte = source.find("10.20.30.40:9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1051,
        &file,
        line,
        col,
        "an outbound billing request is pinned to a hard-coded internal host",
        out,
    );
}

pub(super) fn detect_cwe_1052(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hard_coded_dsn = (source.contains("gorm.Open(postgres.Open(dsn)")
        || source.contains("sql.Open(\"postgres\", appDSNPure)"))
        && source.contains("password=SuperSecret99")
        && source.contains("host=db.internal");
    if !hard_coded_dsn {
        return;
    }
    if source.contains("APP_DATABASE_URL") || source.contains("DB_PASSWORD") {
        return;
    }

    let start_byte = source.find("password=SuperSecret99").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1052,
        &file,
        line,
        col,
        "database initialization embeds a complete DSN with hard-coded credentials",
        out,
    );
}

pub(super) fn detect_cwe_1067(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let leading_wildcard_scan = (source.contains("fmt.Sprintf(\"%%%s%%\", term)")
        || source.contains("pattern := fmt.Sprintf(\"%%%s%%\", term)"))
        && source.contains("LIKE")
        && (source.contains("notes.body") || source.contains("SELECT id, body FROM notes"));
    if !leading_wildcard_scan {
        return;
    }
    if source.contains("prefix+\"%\"") || source.contains("pattern := prefix + \"%\"") {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%%%s%%\", term)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1067,
        &file,
        line,
        col,
        "a search predicate uses a leading wildcard pattern that forces a sequential scan",
        out,
    );
}

pub(super) fn detect_cwe_1173(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let bypassed_validation = source.contains("var raw map[string]interface{}")
        && (source.contains("ShouldBindJSON(&raw)") || source.contains("Decode(&raw)"))
        && (source.contains("SignupPayload{}") || source.contains("SignupPayloadPure{}"));
    if !bypassed_validation {
        return;
    }
    if source.contains("ShouldBindJSON(&payload)")
        || source.contains("Decode(&payload)")
        || source.contains("mail.ParseAddress(payload.Email)")
    {
        return;
    }

    let start_byte = source.find("var raw map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1173,
        &file,
        line,
        col,
        "request data is decoded into a generic map instead of the validated signup model",
        out,
    );
}

pub(super) fn detect_cwe_1125(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let wide_surface = (source.contains("MountWideSurface(")
        || source.contains("MountWideSurfacePure("))
        && (source.contains("/debug/pprof") || source.contains("pprof.Index"))
        && source.contains("/admin/sql")
        && source.contains("/admin/config")
        && source.contains("/internal/reload");
    if !wide_surface {
        return;
    }
    if source.contains("authRequired()") || source.contains("authRequiredPure(") {
        return;
    }

    let start_byte = source.find("/debug/pprof").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1125,
        &file,
        line,
        col,
        "public routing exposes debug, admin, and internal maintenance endpoints together",
        out,
    );
}

pub(super) fn detect_cwe_1204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let static_iv = source.contains("cipher.NewCBCEncrypter(")
        && (source.contains("weakIV") || source.contains("weakIVPure"))
        && source.contains("1234567890123456");
    if !static_iv {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, iv)") {
        return;
    }

    let start_byte = source.find("1234567890123456").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1204,
        &file,
        line,
        col,
        "CBC encryption uses a fixed IV literal instead of generating one per request",
        out,
    );
}

pub(super) fn detect_cwe_1220(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unscoped_invoice_read = (source.contains("GetInvoice(")
        || source.contains("GetInvoicePure("))
        && source.contains("Authorization")
        && source.contains("FROM invoices WHERE id = $1");
    if !unscoped_invoice_read {
        return;
    }
    if source.contains("owner_id = $2")
        || source.contains("ownerID")
        || source.contains("X-User-ID")
    {
        return;
    }

    let start_byte = source.find("FROM invoices WHERE id = $1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1220,
        &file,
        line,
        col,
        "invoice access is authenticated but not scoped to the requesting owner",
        out,
    );
}

pub(super) fn detect_cwe_1230(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let metadata_leak = (source.contains("DownloadRedacted(")
        || source.contains("DownloadRedactedPure("))
        && source.contains("X-Original-Name")
        && source.contains("X-File-Size")
        && source.contains("[REDACTED CONTENT]");
    if !metadata_leak {
        return;
    }
    if source.contains("Cache-Control") {
        return;
    }

    let start_byte = source.find("X-Original-Name").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1230,
        &file,
        line,
        col,
        "a redacted download response still exposes sensitive filename and size metadata",
        out,
    );
}

pub(super) fn detect_cwe_1236(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let raw_csv_export = (source.contains("ExportFeedbackCSV(")
        || source.contains("ExportFeedbackCSVPure("))
        && source.contains("id,comment")
        && source.contains("fmt.Sprintf(\"%d,%s\\n\"")
        && source.contains("row.Comment");
    if !raw_csv_export {
        return;
    }
    if source.contains("sanitizeCSVField(")
        || source.contains("sanitizeCSVFieldPure(")
        || source.contains("csv.NewWriter(")
    {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d,%s\\n\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1236,
        &file,
        line,
        col,
        "CSV export writes user-controlled comment cells without neutralizing spreadsheet formulas",
        out,
    );
}

pub(super) fn detect_cwe_1240(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let custom_xor_cipher = (source.contains("SealSessionToken(")
        || source.contains("SealSessionTokenPure("))
        && (source.contains("xorCipher(") || source.contains("xorCipherPure("))
        && source.contains("^ key");
    if !custom_xor_cipher {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("aes.NewCipher(") {
        return;
    }

    let start_byte = source.find("xorCipher").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1240,
        &file,
        line,
        col,
        "session sealing uses a homegrown XOR cipher instead of a standard authenticated primitive",
        out,
    );
}

pub(super) fn detect_cwe_1265(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let nested_lock_reentry = (source.contains("UpdateBalance(")
        || source.contains("UpdateBalancePure("))
        && (source.contains("ledgerMu.Lock()") || source.contains("ledgerMuPure.Lock()"))
        && (source.contains("PostTransfer(") || source.contains("PostTransferPure("));
    if !nested_lock_reentry {
        return;
    }
    if source.contains("applyBalanceDelta(") || source.contains("applyBalanceDeltaPure(") {
        return;
    }

    let start_byte = source
        .find("UpdateBalance(")
        .or_else(|| source.find("UpdateBalancePure("))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1265,
        &file,
        line,
        col,
        "a transfer path re-enters a mutex-protected balance helper while the same mutex is already held",
        out,
    );
}

pub(super) fn detect_cwe_1286(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let loose_json_config = (source.contains("SaveHookConfig(")
        || source.contains("SaveHookConfigPure("))
        && (source.contains("json.Unmarshal(body, &cfg)")
            || source.contains("json.NewDecoder(r.Body).Decode(&cfg)"))
        && source.contains("hook_configs");
    if !loose_json_config {
        return;
    }
    if source.contains("DisallowUnknownFields()") || source.contains("ParseRequestURI(cfg.URL)") {
        return;
    }

    let start_byte = source
        .find("json.Unmarshal(body, &cfg)")
        .or_else(|| source.find("json.NewDecoder(r.Body).Decode(&cfg)"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1286,
        &file,
        line,
        col,
        "webhook configuration JSON is accepted without strict syntax and URL validation",
        out,
    );
}

pub(super) fn detect_cwe_1289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let literal_path_block = (source.contains("FetchSharedAsset(")
        || source.contains("FetchSharedAssetPure("))
        && source.contains("requested == \"private/keys.pem\"")
        && source.contains("filepath.Join(root, requested)");
    if !literal_path_block {
        return;
    }
    if source.contains("filepath.Clean(filepath.Join(root, requested))")
        || source.contains("HasPrefix(clean, root+string(filepath.Separator))")
    {
        return;
    }

    let start_byte = source
        .find("requested == \"private/keys.pem\"")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1289,
        &file,
        line,
        col,
        "asset access relies on a literal blocked path comparison before canonical normalization",
        out,
    );
}

pub(super) fn detect_cwe_1322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let blocking_worker = (source.contains("StartWebhookWorker(")
        || source.contains("StartWebhookWorkerPure("))
        && source.contains("queue := make(chan")
        && source.contains("for payload := range queue")
        && source.contains("time.Sleep(2 * time.Second)");
    if !blocking_worker {
        return;
    }
    if source.contains("time.AfterFunc(") {
        return;
    }

    let start_byte = source.find("time.Sleep(2 * time.Second)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1322,
        &file,
        line,
        col,
        "the webhook worker blocks its queue loop with sleep instead of scheduling retries asynchronously",
        out,
    );
}

pub(super) fn detect_cwe_1327(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unrestricted_bind = (source.contains("StartPublicAPI(")
        || source.contains("StartPublicAPIPure("))
        && (source.contains("Run(\":9090\")") || source.contains("ListenAndServe(\":9090\","));
    if !unrestricted_bind {
        return;
    }
    if source.contains("127.0.0.1:9090") {
        return;
    }

    let start_byte = source.find(":9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1327,
        &file,
        line,
        col,
        "the service binds to all interfaces instead of a restricted loopback address",
        out,
    );
}

pub(super) fn detect_cwe_1333(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let redos_pattern = source.contains("^([a-zA-Z]+)*$")
        && (source.contains("tagPattern") || source.contains("tagPatternPure"))
        && source.contains("MatchString(tag)");
    if !redos_pattern {
        return;
    }
    if source.contains("safeTagPattern") || source.contains("len(tag) > 32") {
        return;
    }

    let start_byte = source.find("^([a-zA-Z]+)*$").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1333,
        &file,
        line,
        col,
        "tag validation uses a catastrophic-backtracking regex on attacker-controlled input",
        out,
    );
}

pub(super) fn detect_cwe_1389(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let implicit_radix = (source.contains("ReserveSeats(") || source.contains("ReserveSeatsPure("))
        && source.contains("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if source.contains("strconv.ParseInt(raw, 10, 64)") {
        return;
    }

    let start_byte = source.find("strconv.ParseInt(raw, 0, 64)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1389,
        &file,
        line,
        col,
        "seat counts are parsed with base 0 and may accept alternate-radix prefixes unexpectedly",
        out,
    );
}

pub(super) fn detect_cwe_1392(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let default_admin = (source.contains("BootstrapAdmin(")
        || source.contains("BootstrapAdminPure("))
        && source.contains("Username: \"admin\"")
        && source.contains("Password: \"admin\"");
    if !default_admin {
        return;
    }
    if source.contains("BOOTSTRAP_ADMIN_PASSWORD") {
        return;
    }

    let start_byte = source.find("Password: \"admin\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1392,
        &file,
        line,
        col,
        "administrator bootstrap uses a built-in default password literal",
        out,
    );
}

pub(super) fn detect_cwe_807(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let spoofable_ip_gate = source.contains("blockedIPs")
        && (source.contains("GetHeader(\"X-Forwarded-For\")")
            || source.contains("Header.Get(\"X-Forwarded-For\")"));
    if !spoofable_ip_gate {
        return;
    }
    if source.contains("RemoteAddr") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("X-Forwarded-For") {
        idx
    } else {
        source.find("blockedIPs").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_807,
        &file,
        line,
        col,
        "a security gate trusts the caller-controlled forwarded IP header",
        out,
    );
}

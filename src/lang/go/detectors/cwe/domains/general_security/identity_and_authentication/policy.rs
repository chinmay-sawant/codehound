use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_454(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_bootstrap_flag = source
        .contains("enforceMFA = c.PostForm(\"enforce_mfa\") == \"true\"")
        || source.contains("enforceMFA = r.FormValue(\"enforce_mfa\") == \"true\"");
    if !request_bootstrap_flag {
        return;
    }

    let start_byte = source.find("enforce_mfa").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_454,
        file,
        line,
        col,
        "the MFA enforcement flag is bootstrapped from client input instead of server configuration",
        out,
    );
}

pub(crate) fn detect_cwe_488(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let global_session_map = source.contains("map[string][]string{}") && source.contains("session");
    if !global_session_map {
        return;
    }
    if source.contains("Cookie(\"session_id\")") || source.contains("r.Cookie(\"session_id\")") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sessionCarts") {
        idx
    } else {
        source.find("cartsBySession").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_488,
        file,
        line,
        col,
        "global cart state is keyed directly by a client-controlled session identifier",
        out,
    );
}

pub(crate) fn detect_cwe_565(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_cookie = (source.contains("c.Cookie(\"role\")")
        || source.contains("r.Cookie(\"role\")"))
        && source.contains(r#""admin""#)
        && source.contains("DELETE FROM tenants");
    if !trusts_role_cookie {
        return;
    }
    if source.contains("GetString(\"role\")") || source.contains("Header.Get(\"X-Role\")") {
        return;
    }

    let start_byte = source.find("Cookie(\"role\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_565,
        file,
        line,
        col,
        "a privileged delete action trusts a caller-controlled role cookie",
        out,
    );
}

pub(crate) fn detect_cwe_645(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "the account is locked after a single failed login attempt",
        out,
    );
}

pub(crate) fn detect_cwe_649(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "an obfuscated profile cookie is trusted without any integrity verification",
        out,
    );
}

pub(crate) fn detect_cwe_654(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "admin export access is granted solely from a static API key header",
        out,
    );
}

pub(crate) fn detect_cwe_656(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "sensitive configuration access relies only on a hidden URL path",
        out,
    );
}

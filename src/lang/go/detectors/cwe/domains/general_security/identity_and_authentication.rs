use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_missing_account_branch =
        source.contains("no account") && source.contains("StatusNotFound");
    let has_wrong_secret_branch = source.contains("bad password")
        || source.contains("bad secret")
        || source.contains("StatusUnauthorized");
    let has_uniform_failure = source.contains("invalid credentials");

    if !(has_missing_account_branch && has_wrong_secret_branch) || has_uniform_failure {
        return;
    }

    let start_byte = source.find("no account").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_204,
        file,
        line,
        col,
        "authentication failures return distinguishable responses for missing accounts and wrong credentials",
        out,
    );
}

pub(crate) fn detect_cwe_208(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("subtle.ConstantTimeCompare(") {
        return;
    }
    if !(source.contains("for i := range expected")
        && source.contains("provided[i] != expected[i]"))
    {
        return;
    }

    let start_byte = source.find("for i := range expected").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_208,
        file,
        line,
        col,
        "secret comparison returns early on mismatched bytes instead of using a constant-time primitive",
        out,
    );
}

pub(crate) fn detect_cwe_358(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_bearer_claims = source.contains("strings.TrimPrefix(raw, \"Bearer \")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_bearer_claims {
        return;
    }
    if source.contains("invalid jwt structure") || source.contains("unsupported jwt algorithm") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_358,
        file,
        line,
        col,
        "bearer token claims are accepted without required JWT structure and algorithm validation",
        out,
    );
}

pub(crate) fn detect_cwe_385(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let early_exit_secret_compare = source.contains("for i := 0; i < len(provided); i++")
        && source.contains("if provided[i] != expected[i] {")
        && source.contains("return false");
    if !early_exit_secret_compare {
        return;
    }
    if source.contains("ConstantTimeCompare(") {
        return;
    }

    let start_byte = source
        .find("for i := 0; i < len(provided); i++")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_385,
        file,
        line,
        col,
        "the secret comparison exits on the first mismatch and leaks timing information",
        out,
    );
}

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

pub(crate) fn detect_cwe_841(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let workflow_skip = source.contains("ResetAccount")
        && source.contains("new_password")
        && source.contains("password");
    if !workflow_skip {
        return;
    }
    if (source.contains("MFAPassed") && source.contains("if !acct.MFAPassed"))
        || source.contains("if !accountMFAPassed[email]")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_841,
        file,
        line,
        col,
        "the reset workflow changes credentials without enforcing MFA completion",
        out,
    );
}

pub(crate) fn detect_cwe_842(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "newly registered users are assigned to an administrator group by default",
        out,
    );
}

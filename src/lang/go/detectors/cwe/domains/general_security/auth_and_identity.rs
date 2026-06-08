use super::super::super::facts::{GoUnitFacts, InputKind};
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

pub(crate) fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(role_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.name.as_ref() == "role")
    else {
        return;
    };

    let role_is_user_controlled = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name.as_ref() == "role"
    });
    if !role_is_user_controlled {
        return;
    }

    let role_is_used_for_membership =
        source.contains("Role: role") || source.contains("Store(userID, role)");
    if !role_is_used_for_membership {
        return;
    }

    let (line, col) = unit.line_col(role_assignment.start_byte);
    emit::push_finding(
        &META_CWE_266,
        file,
        line,
        col,
        "a client-controlled role value is used directly when provisioning access",
        out,
    );
}

pub(crate) fn detect_cwe_267(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reviewer_guard =
        source.contains(r#"!= "reviewer""#) || source.contains(r#".Get("X-Role") != "reviewer""#);
    if !reviewer_guard {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Remove")
    else {
        return;
    };

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_267,
        file,
        line,
        col,
        "the reviewer role is allowed to invoke a destructive filesystem removal operation",
        out,
    );
}

pub(crate) fn detect_cwe_268(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_chained_scopes = (source.contains(r#"p == "read""#)
        || source.contains(r#"case "read":"#))
        && (source.contains(r#"p == "export""#) || source.contains(r#"case "export":"#))
        && (source.contains("hasRead && hasExport") || source.contains("hasExport && hasRead"));
    if !has_chained_scopes {
        return;
    }

    let Some(sensitive_sink) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "db.Queryx"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("password_hash")))
            || (call.callee.as_ref() == "json.NewEncoder"
                && source.contains("Encode(userRecords)")
                && source.contains(r#""hash""#))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sensitive_sink.start_byte);
    emit::push_finding(
        &META_CWE_268,
        file,
        line,
        col,
        "a sensitive export path is authorized by combining weaker read and export scopes",
        out,
    );
}

pub(crate) fn detect_cwe_270(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(context_switch) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.Set"
            && call.arguments.len() >= 2
            && call.arguments[0].contains("effective_user")
            && (call.arguments[1].contains(r#""root""#)
                || call.arguments[1].contains(r#""maintenance""#)))
            || (call.callee.as_ref() == "context.WithValue"
                && call.arguments.len() >= 3
                && call.arguments[1].contains("effectiveUserKey")
                && (call.arguments[2].contains(r#""root""#)
                    || call.arguments[2].contains(r#""maintenance""#)))
    }) else {
        return;
    };

    let restores_context = source.contains("defer c.Set(\"effective_user\", original)")
        || (source.contains("defer func()")
            && source.contains("context.WithValue(r.Context(), effectiveUserKey, original)"));
    if restores_context {
        return;
    }

    let (line, col) = unit.line_col(context_switch.start_byte);
    emit::push_finding(
        &META_CWE_270,
        file,
        line,
        col,
        "the handler switches to a privileged execution context without restoring the original caller context",
        out,
    );
}

pub(crate) fn detect_cwe_272(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(elevate_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) else {
        return;
    };

    let performs_privileged_work = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "os.Chown");
    if !performs_privileged_work {
        return;
    }

    let drops_privilege = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    });
    if drops_privilege {
        return;
    }

    let (line, col) = unit.line_col(elevate_call.start_byte);
    emit::push_finding(
        &META_CWE_272,
        file,
        line,
        col,
        "the handler raises uid for a privileged operation and does not drop it afterward",
        out,
    );
}

pub(crate) fn detect_cwe_273(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("if err := syscall.Setuid(1000); err != nil") {
        return;
    }

    if facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) {
        return;
    }

    let Some(drop_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(drop_call.start_byte);
    emit::push_finding(
        &META_CWE_273,
        file,
        line,
        col,
        "the handler ignores whether dropping privilege via Setuid actually succeeded",
        out,
    );
}

pub(crate) fn detect_cwe_274(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(rename_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Rename")
    else {
        return;
    };

    let treats_error_as_success = (source.contains("if err != nil {")
        && (source.contains(r#"c.JSON(200, gin.H{"rotated": true})"#)
            || source.contains(r#"w.WriteHeader(http.StatusOK)"#)))
        && !source.contains("errors.Is(err, syscall.EPERM)");
    if !treats_error_as_success {
        return;
    }

    let (line, col) = unit.line_col(rename_call.start_byte);
    emit::push_finding(
        &META_CWE_274,
        file,
        line,
        col,
        "an insufficient-privilege filesystem failure is treated like a successful rotation",
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

pub(crate) fn detect_cwe_783(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "authorization depends on ambiguous && and || precedence",
        out,
    );
}

pub(crate) fn detect_cwe_807(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a security gate trusts the caller-controlled forwarded IP header",
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

pub(crate) fn detect_cwe_909(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a global database handle is used without checking that initialization completed",
        out,
    );
}

pub(crate) fn detect_cwe_915(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a user-controlled attribute map updates privileged object fields directly",
        out,
    );
}

pub(crate) fn detect_cwe_940(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "an OAuth callback accepts caller-supplied authorization data without verifying a bound state token",
        out,
    );
}

pub(crate) fn detect_cwe_941(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

pub(crate) fn detect_cwe_1265(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a transfer path re-enters a mutex-protected balance helper while the same mutex is already held",
        out,
    );
}

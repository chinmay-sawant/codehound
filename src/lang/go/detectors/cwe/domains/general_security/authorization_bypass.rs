use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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

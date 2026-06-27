use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_603(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_auth_header = facts.source_index.has("X-Authenticated")
        && facts.source_index.has(r#""true""#)
        && facts.source_index.has("UPDATE billing SET plan");
    if !trusts_auth_header {
        return;
    }
    if facts.source_index.has_any(&[r#"GetString("uid")"#, r#"Header.Get("X-UID")"#]) {
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

pub(crate) fn detect_cwe_613(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let non_expiring_cookie = (facts.source_index.has_any(&[r#"SetCookie("sid", sid, 0,"#, r#"http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})"#]))
        && facts.source_index.has("LogoutHandler");
    if !non_expiring_cookie {
        return;
    }
    if facts.source_index.has_any(&["revokedSessions[sid]", "revokedSessions[c.Value]", "MaxAge: 900", ", 900,"])
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

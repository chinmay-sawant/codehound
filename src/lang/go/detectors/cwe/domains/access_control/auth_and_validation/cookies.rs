use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Access-control B3 trust freeze (auth_and_validation/cookies.rs).
// Bounded family: CWE-603 + CWE-613 only (2 rules). Sibling auth_flows/auth_tokens deferred.
// Primary evidence is SourceIndex corpus co-presence (header/SQL/cookie/handler names),
// not call_facts/AST. Route, role, and middleware-style names are treated as policy
// evidence unless a stronger local proof exists — none does here.
// Proposed maturity: fixture-only (integrator applies maturity.rs).
// See plans/v0.0.5/pr-cwe-trust-auth-validation.md.

pub(crate) fn detect_cwe_603(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): client auth header name + "true" + billing UPDATE
    // co-presence. Header/route naming is policy evidence, not verified authz proof.
    // Negative gate: GetString("uid") / Header.Get("X-UID") — server-validated subject.
    // Call-facts cannot prove "trusts caller header" without the corpus header+SQL shape;
    // keep SI primary. Not a generalized client-auth detector.
    let trusts_auth_header = facts.source_index.has("X-Authenticated")
        && facts.source_index.has(r#""true""#)
        && facts.source_index.has("UPDATE billing SET plan");
    if !trusts_auth_header {
        return;
    }
    if facts
        .source_index
        .has_any(&[r#"GetString("uid")"#, r#"Header.Get("X-UID")"#])
    {
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

    // Primary signal (fixture-literal): exact non-expiring sid cookie SetCookie shapes
    // (gin maxAge 0 / stdlib Cookie without MaxAge) co-present with LogoutHandler name.
    // Handler naming is policy evidence; MaxAge literals are corpus markers.
    // Negative gate: revokedSessions[sid|c.Value] / MaxAge: 900 / ", 900," short TTL.
    // Call-facts for SetCookie alone cannot prove missing server-side revocation +
    // non-expiring cookie without LogoutHandler + sid corpus co-signals; keep SI primary.
    let non_expiring_cookie = (facts.source_index.has_any(&[
        r#"SetCookie("sid", sid, 0,"#,
        r#"http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})"#,
    ])) && facts.source_index.has("LogoutHandler");
    if !non_expiring_cookie {
        return;
    }
    if facts.source_index.has_any(&[
        "revokedSessions[sid]",
        "revokedSessions[c.Value]",
        "MaxAge: 900",
        ", 900,",
    ]) {
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

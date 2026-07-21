use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Access-control R4 trust freeze (auth_and_validation/auth_tokens.rs).
// Bounded family: CWE-294, 301, 303, 322, 408 (5 rules; whole file — ~147 lines).
// Primary evidence is SourceIndex corpus co-presence and one source-order check (408),
// not call_facts/AST. Handler/form field names and exact response literals are policy
// evidence unless a stronger local proof exists — none does here.
// Proposed maturity: fixture-only for all five (integrator applies maturity.rs).
// See plans/v0.0.6/evidence-r4-auth-tokens.md and pr-r4-auth-tokens.md.

pub(crate) fn detect_cwe_294(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact auth_token form loaders (gin PostForm /
    // stdlib FormValue) without nonce/replay tracking co-signals.
    // Negative gate: LoadOrStore(nonce, true) / spentNonces / PostForm|FormValue("nonce").
    // Call-facts cannot prove replay acceptance without corpus auth_token + nonce shape;
    // keep SI primary. Not a generalized token-replay detector.
    let loads_auth_token = facts.source_index.has_any(&[
        r#"c.PostForm("auth_token")"#,
        r#"r.FormValue("auth_token")"#,
    ]);
    if !loads_auth_token {
        return;
    }

    let has_nonce_tracking = facts.source_index.has_any(&[
        "LoadOrStore(nonce, true)",
        "spentNonces",
        r#"PostForm("nonce")"#,
        r#"FormValue("nonce")"#,
    ]);
    if has_nonce_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("auth_token") {
        idx
    } else {
        return;
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_294,
        file,
        line,
        col,
        "the login flow accepts an authentication token without nonce tracking or replay detection",
        out,
    );
}

pub(crate) fn detect_cwe_301(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact challenge→proof echo shapes (gin H / JSON /
    // map literal with proof: challenge). Challenge field naming is policy evidence.
    // Negative gate: hmac.New( / EncodeToString( — server-side MAC proof instead of echo.
    // Call-facts for json.Encode alone cannot prove reflection without corpus proof literal;
    // keep SI primary. Not a generalized mutual-auth detector.
    let echoes_challenge = facts.source_index.has_any(&[
        r#"gin.H{"proof": challenge}"#,
        r#"{"proof": challenge}"#,
        r#"map[string]string{"proof": challenge}"#,
    ]);
    if !echoes_challenge {
        return;
    }
    if facts
        .source_index
        .has_any(&["hmac.New(", "EncodeToString("])
    {
        return;
    }

    let start_byte = source.find("challenge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_301,
        file,
        line,
        col,
        "the server reflects the client challenge directly as the authentication proof",
        out,
    );
}

pub(crate) fn detect_cwe_303(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): hmac.New( + mac.Sum(nil) + exact
    // string(expected) == sig comparison (not hmac.Equal / ConstantTimeCompare).
    // Negative gate: implicit — safe fixtures use subtle.ConstantTimeCompare instead.
    // Call-facts for hmac.New alone fire on legitimate HMAC paths; the == sig string
    // is the museum boundary. Neighbor CWE-208/385 own early-exit byte loops, not == MAC.
    // keep SI primary. Not a generalized MAC-verification detector.
    if !facts.source_index.has("hmac.New(") || !facts.source_index.has("mac.Sum(nil)") {
        return;
    }
    if !facts.source_index.has("string(expected) == sig") {
        return;
    }

    let start_byte = source.find("string(expected) == sig").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_303,
        file,
        line,
        col,
        "the computed MAC is compared to user input with string equality instead of constant-time verification",
        out,
    );
}

pub(crate) fn detect_cwe_322(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): tls.Dial( co-present with exact
    // InsecureSkipVerify: true literal (relay/key-exchange museum from fixtures).
    // Negative gate: implicit — safe fixtures use RootCAs / VerifyHostname instead.
    // Call-facts for tls.Dial alone cannot prove skip-verify without corpus literal;
    // keep SI primary. Sole InsecureSkipVerify owner in catalog; still fixture-shaped.
    if !facts.source_index.has("tls.Dial(") || !facts.source_index.has("InsecureSkipVerify: true") {
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

pub(crate) fn detect_cwe_408(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact orders SELECT + Authorization header both
    // present with source-order proof (query byte offset before Authorization).
    // Negative gate: implicit — safe fixture checks Authorization before Query.
    // Call-facts/db.Query alone cannot prove auth-order without corpus SQL + header shape;
    // keep SI + source-order primary. Not a generalized early-amplification detector.
    let query_before_auth = (facts
        .source_index
        .has("SELECT * FROM orders WHERE tenant_id = ?")
        && facts.source_index.has("Authorization"))
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

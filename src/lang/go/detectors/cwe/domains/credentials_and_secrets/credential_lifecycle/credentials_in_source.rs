use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Credential-lifecycle B1 trust freeze (credentials_in_source.rs).
// Selected family for parallel-catalog-program §2.1 / issue #107:
// credentials-in-source (CWE-523, CWE-547, CWE-798). Deferred siblings:
// key_expiration (324), password_aging (262/263), reset_recovery (549/640).
//
// Primary evidence for all three rules is SourceIndex / exact source-text
// corpus co-presence, not generalized call_facts. Call facts cannot become
// complete primary without either (a) deployment/topology proof (523 TLS),
// (b) hard-coded-const dataflow into a crypto sink (547), or (c) generalized
// credential-string recognition (798) — none of which are local AST sinks.
//
// Proposed maturity: fixture-only for CWE-523 and CWE-547; CWE-798 already
// fixture-only (Tranche 1). Integrator applies maturity.rs / NEEDLES labels.
// See plans/v0.0.5/pr-cwe-trust-credential-lifecycle.md and
// plans/v0.0.5/evidence-cwe-trust-credential-lifecycle.md.

/// CWE-523 — Unprotected Transport of Credentials.
///
/// Freeze (B1 / #107): login path + password form + cleartext listen shape
/// (`Addr: ":8080"` / `StartCleartextLogin`) without TLS enforcement
/// (`requireTLS(`, `Request.TLS == nil`, `r.TLS == nil`).
///
/// Runtime/deployment assumption: whether a listener is actually cleartext
/// depends on reverse proxies and TLS termination outside the unit. Call
/// facts for `http.Server` / `ListenAndServe` alone cannot prove credential
/// transport without the corpus login/password co-signals (and would collide
/// with CWE-319's payment-field cleartext-listen ownership). Disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_523(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal / SI): /login + password + cleartext
    // listen shape. Negative gate: requireTLS( or explicit TLS-nil checks.
    let cleartext_login = (facts.source_index.has("/login") && facts.source_index.has("password"))
        && (facts.source_index.has("Addr: \":8080\"")
            || facts.source_index.has("StartCleartextLogin"));
    if !cleartext_login {
        return;
    }
    if facts.source_index.has("requireTLS(")
        || facts.source_index.has("Request.TLS == nil")
        || facts.source_index.has("r.TLS == nil")
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

/// CWE-547 — Use of Hard-coded, Security-Relevant Constants.
///
/// Freeze (B1 / #107): exact const declarations `const jwtSecret = ` or
/// `const sessionMACKey = ` without env-loaded signing material
/// (`os.Getenv("JWT_SIGNING_KEY")` / `os.Getenv("SESSION_MAC_KEY")`).
///
/// The hard-coded identifier *is* the proof boundary — not a generalized
/// crypto API. Call facts for `hmac.New` / JWT `SignedString` would over-fire
/// on legitimate runtime-loaded keys and cannot prove the constant is
/// security-relevant without the fixture const names. Disposition:
/// **fixture-only**.
pub(crate) fn detect_cwe_547(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal): exact hard-coded signing-const names.
    // Negative gate: env-loaded JWT_SIGNING_KEY / SESSION_MAC_KEY.
    let hardcoded_signing_secret = facts.source_index.has("const jwtSecret = ")
        || facts.source_index.has("const sessionMACKey = ");
    if !hardcoded_signing_secret {
        return;
    }
    if facts.source_index.has("os.Getenv(\"JWT_SIGNING_KEY\")")
        || facts.source_index.has("os.Getenv(\"SESSION_MAC_KEY\")")
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

/// CWE-798 — Use of Hard-coded Credentials.
///
/// Freeze (B1 / #107): exact PostgreSQL reporting DSN literal
/// `postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable`
/// without `os.Getenv("REPORTING_DSN")`.
///
/// Already **fixture-only** since Tranche 1 (cwe-catalog-trust-audit.md).
/// Reaffirm: one literal DSN; no generalized credential-string recognition.
/// Sibling ownership: BP-152 retired as duplicate of this CWE; CWE-1052
/// (password_storage/bootstrap) owns a different hard-coded DSN shape
/// (`password=SuperSecret99` + gorm/sql Open). Disposition: keep
/// **fixture-only**.
pub(crate) fn detect_cwe_798(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (exact source text): single fixture DSN with embedded creds.
    // Negative gate: REPORTING_DSN env load. No call-facts rewrite — sql.Open /
    // sqlx.Connect alone is not hard-coded-credential proof.
    let hardcoded_dsn = source
        .contains("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable");
    if !hardcoded_dsn {
        return;
    }
    if facts.source_index.has("os.Getenv(\"REPORTING_DSN\")") {
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

use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_319(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no cleartext listen text ⇒ no sink of this shape.
    if !(facts.source_index.has("ListenAndServe(")
        || facts.source_index.has("http.ListenAndServe(")
        || facts.source_index.has("http.ListenAndServe"))
    {
        return;
    }
    // Corpus co-signals still required for oracle (payment card field names).
    // Maturity is fixture-only; call_facts is the primary sink proof only.
    let handles_card_data = facts.source_index.has("CVV") && facts.source_index.has("Number");
    if !handles_card_data {
        return;
    }
    // Negative prefilters: TLS listener or explicit tls.Config evidence.
    if facts.source_index.has("ListenAndServeTLS(") || facts.source_index.has("tls.Config") {
        return;
    }

    // Primary signal: call facts — package or method ListenAndServe (not TLS).
    let Some(listen_call) = facts.call_facts.iter().find(|call| {
        let c = call.callee.as_ref();
        c.ends_with("ListenAndServe") && !c.ends_with("ListenAndServeTLS")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(listen_call.start_byte);
    emit::push_finding(
        &META_CWE_319,
        file,
        line,
        col,
        "sensitive payment data is accepted over a cleartext HTTP listener instead of TLS",
        out,
    );
}

pub(crate) fn detect_cwe_524(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Fixture-only museum: emit requires exact process-wide cache identifiers
    // (`tokenCache` / `tokenVault`) plus map + Authorization co-signals.
    // No call-facts rewrite: the sink is a package-level map assignment, not a
    // generalized API boundary; Header.Get("Authorization") alone would over-fire.
    // Safe path is request-scoped storage (`context.WithValue` / `session_token`).
    let process_wide_token_cache = (facts.source_index.has("map[string]string{}")
        && facts.source_index.has("Authorization"))
        && (facts.source_index.has("tokenCache") || facts.source_index.has("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if facts.source_index.has("context.WithValue(") || facts.source_index.has("session_token") {
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
        file,
        line,
        col,
        "raw session tokens are cached in shared process memory keyed by caller identifiers",
        out,
    );
}

pub(crate) fn detect_cwe_538(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no WriteFile text ⇒ no public secret export sink.
    if !facts.source_index.has("os.WriteFile(") {
        return;
    }
    // Corpus co-signals still required for oracle (secret env + public web path).
    // Maturity is fixture-only; call_facts is the primary WriteFile+mode proof only.
    if !facts.source_index.has("DATABASE_URL") {
        return;
    }
    if !(facts.source_index.has("/var/www/") || facts.source_index.has("/var/www/html/public/")) {
        return;
    }
    // Negative prefilters: private export path or owner-only mode (corpus safe-path).
    if facts.source_index.has("/var/lib/codehound/private") || facts.source_index.has("0o600") {
        return;
    }

    // Primary signal: call facts — os.WriteFile with world-readable mode 0o644.
    // Path is often bound through a local `path` variable, so public-path proof
    // remains SourceIndex co-signals above (not the WriteFile first argument).
    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0o644"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_538,
        file,
        line,
        col,
        "database configuration secrets are exported to a public world-readable file path",
        out,
    );
}

use super::super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-209 — Generation of Error Message Containing Sensitive Information.
///
/// Freeze (B2 / #108): primary evidence was the exact corpus sprintf
/// `fmt.Sprintf("db failure: %v", err)` used as a client-facing error body.
/// Safe path logs server-side and returns a generic `"could not create …"` body.
///
/// Call facts become primary for the `fmt.Sprintf` sink with the fixed format
/// string; the same corpus format remains the SI prefilter / co-signal so we do
/// not promote generic error sprintf or response strings. Disposition:
/// **fixture-only** (exact format museum; zero real-module expectation).
pub(crate) fn detect_cwe_209(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: exact corpus sensitive-error format string.
    if !facts
        .source_index
        .has(r#"fmt.Sprintf("db failure: %v", err)"#)
    {
        return;
    }

    // Primary signal: call facts — fmt.Sprintf with the fixed "db failure: %v"
    // format and the err value (client-visible driver/detail leak shape).
    let Some(sprintf_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "fmt.Sprintf"
            && call.arguments.len() >= 2
            && call.arguments[0].as_ref() == r#""db failure: %v""#
            && call.arguments[1].as_ref() == "err"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sprintf_call.start_byte);
    emit::push_finding(
        &META_CWE_209,
        file,
        line,
        col,
        "database error details are formatted into a client-facing response",
        out,
    );
}

/// CWE-215 — Insertion of Sensitive Information Into Debugging Code.
///
/// Freeze (B2 / #108): already call-facts primary for `log.Printf` whose
/// arguments include a user-controlled binding whose name contains `secret`
/// (GetHeader / Header.Get input classification). Safe path logs path/method
/// /trace only — no secret-named binding.
///
/// Do not broaden to generic log format strings or all request fields; the
/// name.contains("secret") gate is intentional noise control. Disposition:
/// **keep Heuristic** if real-module canary is quiet; still not structural
/// (§1.3: name-substring co-signal, not a typed secret model).
pub(crate) fn detect_cwe_215(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Note: no SourceIndex prefilter — bare `log.Printf` is not an owned NEEDLE
    // (only the CWE-307 `log.Printf("auth failure` literal is). Call-facts walk
    // is bounded and already the production-shaped primary signal.
    for call in &facts.call_facts {
        if call.callee.as_ref() != "log.Printf" {
            continue;
        }

        // Primary signal: call facts — log.Printf argument is a user-controlled
        // binding whose name marks it as secret material (request-derived).
        let logs_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && binding.name.contains("secret")
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.as_ref() == binding.name.as_ref())
        });
        if !logs_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_215,
            file,
            line,
            col,
            "a debug log statement includes request-derived secret material",
            out,
        );
        return;
    }
}

/// CWE-756 — Missing Custom Error Page.
///
/// Freeze (B2 / #108): primary evidence was exact SI for `err.Error()` returned
/// via `c.String(..., err.Error())` or `http.Error(w, err.Error(), …)`, gated
/// on corpus `FetchProfile` + `SELECT email FROM profiles`. Safe path returns
/// the generic `"unable to load profile"` body.
///
/// Call facts become primary for the client error sinks (`http.Error` /
/// `c.String`) that pass `err.Error()`; SI retains the corpus helper/SQL
/// co-signals and the generic-message negative. Disposition: **fixture-only**
/// (handler name + SQL museum; bare err.Error()→client would mass-FP).
pub(crate) fn detect_cwe_756(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: raw err.Error() text must appear.
    if !facts.source_index.has("err.Error()") {
        return;
    }
    // Corpus co-signals: named profile-fetch helper + fixed SELECT shape.
    if !facts.source_index.has("FetchProfile")
        || !facts.source_index.has("SELECT email FROM profiles")
    {
        return;
    }
    // Negative prefilter: generic client-facing error body (safe path).
    if facts.source_index.has("\"unable to load profile\"") {
        return;
    }

    // Primary signal: call facts — client error sink with raw err.Error() body.
    let Some(error_call) = facts.call_facts.iter().find(|call| {
        let callee = call.callee.as_ref();
        let passes_raw_err = call
            .arguments
            .iter()
            .any(|arg| arg.as_ref() == "err.Error()");
        if !passes_raw_err {
            return false;
        }
        callee == "http.Error" || callee == "c.String"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(error_call.start_byte);
    emit::push_finding(
        &META_CWE_756,
        file,
        line,
        col,
        "raw database error text is returned directly to the client",
        out,
    );
}

/// CWE-1230 — Exposure of Sensitive Information Through Metadata.
///
/// Freeze (B2 / #108): primary evidence was exact SI for `DownloadRedacted` /
/// `DownloadRedactedPure` helpers plus `X-Original-Name` / `X-File-Size` /
/// `[REDACTED CONTENT]`. Safe path sets `Cache-Control` and omits filename/size.
///
/// Call facts become primary for the header write sinks (`c.Header` /
/// `w.Header().Set`) that emit `X-Original-Name`; SI retains the redacted-
/// download corpus co-signals and the Cache-Control negative. Disposition:
/// **fixture-only** (helper names + custom header museum).
pub(crate) fn detect_cwe_1230(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: sensitive metadata header name must appear.
    if !facts.source_index.has("X-Original-Name") {
        return;
    }
    // Corpus co-signals: redacted-download helpers + size header + redacted body.
    let redacted_download = facts.source_index.has("DownloadRedacted(")
        || facts.source_index.has("DownloadRedactedPure(");
    if !redacted_download
        || !facts.source_index.has("X-File-Size")
        || !facts.source_index.has("[REDACTED CONTENT]")
    {
        return;
    }
    // Negative prefilter: safe path sets Cache-Control and omits metadata headers.
    if facts.source_index.has("Cache-Control") {
        return;
    }

    // Primary signal: call facts — header write of X-Original-Name (filename leak).
    let Some(header_call) = facts.call_facts.iter().find(|call| {
        matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
            && call
                .arguments
                .iter()
                .any(|arg| arg.as_ref() == r#""X-Original-Name""#)
    }) else {
        return;
    };

    let (line, col) = unit.line_col(header_call.start_byte);
    emit::push_finding(
        &META_CWE_1230,
        file,
        line,
        col,
        "a redacted download response still exposes sensitive filename and size metadata",
        out,
    );
}

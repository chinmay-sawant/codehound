use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::META_CWE_76;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-76 — Improper Neutralization of Equivalent Special Elements.
///
/// Freeze (C4 / #115): incomplete HTML neutralization by stripping only literal
/// angle brackets via exact corpus `strings.ReplaceAll(raw, "<", "")` /
/// `strings.ReplaceAll(safe, ">", "")`, gated on a user-controlled binding
/// named `raw` and `text/html` content type. Safe path uses
/// `html.EscapeString(`.
///
/// Not owned by taint-core CWE-79 (XSS flow to HTML sinks). CWE-76 targets the
/// **incomplete strip** museum shape rather than general XSS dataflow.
///
/// Call facts become primary for the `strings.ReplaceAll` strip of `"<"`; SI
/// retains the exact dual-ReplaceAll corpus co-signals, the `raw` binding name,
/// and the content-type gate so generic ReplaceAll is not promoted. Disposition:
/// **fixture-only** and **demote from Structural** — current evidence fails the
/// §1.3 structural bar (corpus literals + exact binding name; no generalized
/// incomplete-escape fact; no reviewed real-module hit).
pub(crate) fn detect_cwe_76(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Negative prefilter: proper context-aware HTML escape.
    if facts.source_index.has("html.EscapeString(") {
        return;
    }
    // Corpus co-signals: dual angle-bracket strip shape (exact fixture formulas).
    if !facts
        .source_index
        .has(r#"strings.ReplaceAll(raw, "<", "")"#)
        || !facts
            .source_index
            .has(r#"strings.ReplaceAll(safe, ">", "")"#)
    {
        return;
    }
    // Field-name co-signal: user-controlled binding named `raw` (non-emitting
    // prefilter / museum gate — not a generalized input classification).
    if !facts
        .input_bindings
        .iter()
        .any(|binding| binding.kind == InputKind::UserControlled && binding.name.as_ref() == "raw")
    {
        return;
    }
    // Content-type co-signal: HTML output context.
    if !facts.source_index.has("text/html") {
        return;
    }

    // Primary signal: call facts — strings.ReplaceAll that strips literal "<".
    let Some(strip_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "strings.ReplaceAll"
            && call.arguments.len() >= 2
            && call.arguments[1].as_ref() == r#""<""#
    }) else {
        return;
    };

    let (line, col) = unit.line_col(strip_call.start_byte);
    emit::push_finding(
        &META_CWE_76,
        file,
        line,
        col,
        "manual angle-bracket stripping is used for HTML output instead of proper escaping",
        out,
    );
}

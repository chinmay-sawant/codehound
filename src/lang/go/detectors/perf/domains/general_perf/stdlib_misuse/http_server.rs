//! PERF-102, 120, 122, 126, 127: HTTP server / general misuse detectors.

use std::collections::HashMap;

use super::common::{extract_first_quoted, fmt_contains_verb, is_log_call};
use super::header_allowlist::is_canonical_header;
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-120: `time.Now().Sub(t)` should be `time.Since(t)`.
pub(crate) fn detect_perf_120(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "time.Now" {
            continue;
        }
        // We can't tell from the call-site text whether `.Sub(...)`
        // is being called. Use a short source window: the call
        // expression plus a few characters afterwards.
        let start = call.start_byte.min(unit.source.len());
        let end = (start + 32).min(unit.source.len());
        let window = &unit.source[start..end];
        if !window.contains(".Sub(") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_120,
            file,
            line,
            col,
            "time.Now().Sub(t) should be time.Since(t)",
            out,
        );
    }
}

/// PERF-122: `strings.HasPrefix(s, p)` followed by `s[len(p):]` should
/// be `strings.TrimPrefix(s, p)`.
pub(crate) fn detect_perf_122(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.HasPrefix" {
            continue;
        }
        // Look for a sibling `s[len(p):]` style slice on the receiver
        // argument. We approximate by searching a small source
        // window around the call for a matching slice expression.
        let start = call.start_byte.saturating_sub(64);
        let end = (call.start_byte + 256).min(source.len());
        let window = &source[start..end];
        if !window.contains("len(") || !window.contains(":]") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_122,
            file,
            line,
            col,
            "strings.HasPrefix + slice should be strings.TrimPrefix",
            out,
        );
    }
}

/// PERF-126: `http.CanonicalHeaderKey` applied to a string literal
/// that is already in canonical form. We approximate by checking a
/// curated allowlist of headers that ship canonicalized.
pub(crate) fn detect_perf_126(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "http.CanonicalHeaderKey" {
            continue;
        }
        let arg = call.arguments.first().map(|s| s.as_ref()).unwrap_or("");
        // Strip surrounding quotes.
        let inner = arg.trim_matches('"');
        if !is_canonical_header(inner) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_126,
            file,
            line,
            col,
            "http.CanonicalHeaderKey on an already-canonical header is a no-op",
            out,
        );
    }
}

/// PERF-127: `log.*(fmt.Sprintf("static string"))` — the format
/// string has no verbs, so the Sprintf is a no-op. We approximate by
/// checking that the format string contains no `%` outside of `%%`.
pub(crate) fn detect_perf_127(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if !is_log_call(&call.callee) {
            continue;
        }
        // Look for a fmt.Sprintf inside the arguments. The call
        // facts store the callee name of the outer log call; we
        // need to inspect the source to see if the format string is
        // static.
        let first_arg = call.arguments.first().map(|s| s.as_ref()).unwrap_or("");
        if !first_arg.contains("fmt.Sprintf") {
            continue;
        }
        // Naive verb check: count `%` not followed by another `%`.
        // A real implementation would parse the format string.
        let fmt = extract_first_quoted(first_arg);
        if !fmt_contains_verb(fmt) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_127,
                file,
                line,
                col,
                "log call wraps a fmt.Sprintf with no format verbs; pass the string directly",
                out,
            );
        }
    }
}

/// PERF-102: `w.WriteHeader(...)` called more than once on the
/// same `http.ResponseWriter` in a single handler. Only the first
/// call takes effect; subsequent calls log a warning at runtime.
pub(crate) fn detect_perf_102(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    if !facts.source_index.has(".WriteHeader(") {
        return;
    }

    let src = unit.source.as_bytes();
    let mut calls_by_scope_and_receiver: HashMap<(usize, String), Vec<(usize, bool)>> =
        HashMap::new();
    crate::ast::walk_nodes(unit.tree.root_node(), &["call_expression"], &mut |call| {
        let Ok(text) = call.utf8_text(src) else {
            return;
        };
        let Some((receiver, _)) = text.split_once(".WriteHeader(") else {
            return;
        };
        let Some(scope_start) = enclosing_callable_start(call) else {
            return;
        };
        calls_by_scope_and_receiver
            .entry((scope_start, receiver.trim().to_owned()))
            .or_default()
            .push((call.start_byte(), call_is_followed_by_return(call)));
    });

    for calls in calls_by_scope_and_receiver.values() {
        if calls.len() < 2 || calls[..calls.len() - 1].iter().all(|(_, returns)| *returns) {
            continue;
        }
        let (line, col) = unit.line_col(calls[0].0);
        emit::push_finding(
            &META_PERF_102,
            file,
            line,
            col,
            "w.WriteHeader called multiple times; only the first call takes effect",
            out,
        );
    }
}

/// A `return` later in the same direct statement list terminates this write's
/// path before a later lexical WriteHeader call can execute.
fn call_is_followed_by_return(mut node: tree_sitter::Node) -> bool {
    loop {
        let Some(parent) = node.parent() else {
            return false;
        };
        if matches!(parent.kind(), "statement_list" | "block") {
            let mut after_statement = false;
            let mut cursor = parent.walk();
            for sibling in parent.named_children(&mut cursor) {
                if !after_statement {
                    after_statement = sibling.id() == node.id();
                    continue;
                }
                if sibling.kind() == "return_statement" {
                    return true;
                }
            }
            return false;
        }
        if matches!(
            parent.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return false;
        }
        node = parent;
    }
}

fn enclosing_callable_start(mut node: tree_sitter::Node) -> Option<usize> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return Some(parent.start_byte());
        }
        node = parent;
    }
    None
}

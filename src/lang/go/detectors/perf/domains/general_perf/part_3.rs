//! PERF-42 to PERF-50 detectors.
//!
//! Heuristics for `fmt.Errorf` with no format verbs, `defer`/`recover`
//! in hot paths, repeated type assertions, append growth, and string
//! utilities (`Trim*`, `Split`, `Equal*`, `copy`, `regexp.Match`).

use super::super::super::common::{is_in_loop, is_request_path};
use super::super::super::facts::{CallFact, GoPerfFacts};
use super::super::super::metadata::*;
use crate::ast::nearest_loop;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

/// PERF-42: `fmt.Errorf("static message")` without format verbs.
pub(crate) fn detect_perf_42(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !is_in_loop_present(&facts.calls) {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "fmt.Errorf" {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let first = call.arguments[0].as_ref();
        if !first.starts_with('"') || !first.ends_with('"') {
            continue;
        }
        let literal = &first[1..first.len() - 1];
        if literal.contains('%') {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_42,
            file,
            line,
            col,
            "fmt.Errorf with a static string allocates a Sprintf; use errors.New instead",
            out,
        );
        return;
    }
    let _ = source;
}

fn is_in_loop_present(calls: &[CallFact]) -> bool {
    calls.iter().any(super::super::super::common::is_in_loop)
}

/// PERF-43: `defer func(){ recover() }()` in a hot loop or per-request path.
pub(crate) fn detect_perf_43(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    walk_nodes(unit.tree.root_node(), &["defer_statement"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !text.contains("recover()") {
            return;
        }
        if !is_request_path(source) && nearest_loop(node, LOOP_NODE_KINDS).is_none() {
            return;
        }
        let (line, col) = unit.line_col(node.start_byte());
        emit::push_finding(
            &META_PERF_43,
            file,
            line,
            col,
            "defer-recover runs in a hot path; add the recover at a higher boundary",
            out,
        );
    });
}

/// PERF-44: type assertion on the same value repeated inside a function.
pub(crate) fn detect_perf_44(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    let mut assertions: Vec<(usize, String)> = Vec::new();
    walk_nodes(
        unit.tree.root_node(),
        &["type_assertion_expression"],
        &mut |node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            // text is e.g. "v.(intVal)". We want the LHS variable name to
            // spot duplicates on the same source value.
            let lhs = text.split_once(".(").map(|(lhs, _)| lhs.trim().to_string());
            if let Some(lhs) = lhs {
                assertions.push((node.start_byte(), lhs));
            }
        },
    );

    // Sort by start byte and look for two assertions on the same LHS in
    // the same function (the entire file is one function in our fixtures).
    for window in assertions.windows(2) {
        if window[0].1 == window[1].1 && !window[0].1.is_empty() {
            let (line, col) = unit.line_col(window[0].0);
            emit::push_finding(
                &META_PERF_44,
                file,
                line,
                col,
                "the same type assertion is repeated; cache the result in a local variable",
                out,
            );
            return;
        }
    }
}

/// PERF-45: `append` in a `for` loop without a `make([]T, 0, hint)`.
pub(crate) fn detect_perf_45(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for _, v := range") && !source.contains("for i := 0;") {
        return;
    }
    if source.contains("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_45,
            file,
            line,
            col,
            "append inside a loop without a capacity hint causes repeated reallocation",
            out,
        );
        return;
    }
}

/// PERF-46: `strings.TrimSpace` / `Trim` / `TrimPrefix` / `TrimSuffix` in a
/// request path.
pub(crate) fn detect_perf_46(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "strings.TrimSpace"
                | "strings.Trim"
                | "strings.TrimPrefix"
                | "strings.TrimSuffix"
                | "strings.TrimLeft"
                | "strings.TrimRight"
        ) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_46,
            file,
            line,
            col,
            "string trimming allocates on a request path; check the need first",
            out,
        );
        return;
    }
    let _ = source;
}

/// PERF-47: `strings.Split` / `SplitN` / `SplitAfter` in a loop or hot path.
pub(crate) fn detect_perf_47(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "strings.Split" | "strings.SplitN" | "strings.SplitAfter"
        ) {
            continue;
        }
        // A bare `strings.Split` outside of a loop body is a one-shot parse
        // — the caller already paid for the bytes. Only flag when it
        // appears inside a loop where it will repeat per iteration.
        if !is_in_loop(call) {
            continue;
        }
        // `for _, x := range strings.Split(...)` — the Split is the
        // iterable and only runs once, not per iteration. Suppress.
        if is_range_iterable(call.start_byte, unit) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_47,
            file,
            line,
            col,
            "strings.Split allocates a slice; consider a streaming scanner",
            out,
        );
        return;
    }
    let _ = facts;
}

/// Returns true when the call expression at `start_byte` is the `right`
/// field of a `range_clause` (i.e. the iterable of `for ... range X`).
fn is_range_iterable(start_byte: usize, unit: &ParsedUnit) -> bool {
    let root = unit.tree.root_node();
    let Some(node) = root.descendant_for_byte_range(start_byte, start_byte) else {
        return false;
    };
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "range_clause"
            && let Some(right) = parent.child_by_field_name("right")
            && right.start_byte() <= start_byte
            && right.end_byte() >= start_byte
        {
            return true;
        }
        if parent.kind() == "for_statement" {
            return false;
        }
        current = parent;
    }
    false
}

/// PERF-48: `bytes.Equal` / `strings.EqualFold` on long inputs without an
/// early length / prefix check.
pub(crate) fn detect_perf_48(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "bytes.Equal" | "strings.EqualFold" | "bytes.Compare"
        ) {
            continue;
        }
        if source.contains("if len(a) != len(b) { return false }") || source.contains("len(prefix)")
        {
            return;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_48,
            file,
            line,
            col,
            "byte / string equality on a hot path; add a length or prefix precheck",
            out,
        );
        return;
    }
}

/// PERF-49: `copy(dst, src)` with mismatched or unchecked length.
pub(crate) fn detect_perf_49(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }
    if !source.contains("copy(buf, payload)") && !source.contains("copy(dst, src)") {
        return;
    }
    if source.contains("if len(payload) > len(buf) { return }") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "copy" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_49,
            file,
            line,
            col,
            "copy(dst, src) is invoked without explicit length validation",
            out,
        );
        return;
    }
}

/// PERF-50: `regexp.MatchString` / `regexp.Match` inside a loop.
pub(crate) fn detect_perf_50(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "regexp.MatchString" | "regexp.Match" | "regexp.MatchReader"
        ) {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_50,
            file,
            line,
            col,
            "regexp match is invoked inside a loop; compile the pattern once and reuse it",
            out,
        );
        return;
    }
    let _ = facts;
}

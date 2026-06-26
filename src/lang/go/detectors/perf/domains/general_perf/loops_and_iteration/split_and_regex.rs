use super::super::super::super::common::is_in_loop;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-46: `strings.TrimSpace` / `Trim` / `TrimPrefix` / `TrimSuffix` in a
/// request path.
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
pub(super) fn is_range_iterable(start_byte: usize, unit: &ParsedUnit) -> bool {
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

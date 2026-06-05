//! PERF-001 through PERF-008: allocations and expensive operations in loops.
//!
//! All detectors in this module share the same shape: they look up the call
//! / assignment in the precomputed [`GoPerfFacts`], check whether it lives
//! inside a `for_statement`, and emit a finding when no mitigating evidence
//! is present.

use super::super::common::{is_assignment_in_loop, is_in_loop};
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::ast::walk_nodes;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::ast::nearest_loop;
use crate::rules::{Finding, emit};

/// PERF-001: regexp.MustCompile / regexp.Compile inside a loop.
pub(crate) fn detect_perf_1(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "regexp.MustCompile" | "regexp.Compile") {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_1,
            file,
            line,
            col,
            "regular expression compiled inside loop body",
            out,
        );
    }
}

/// PERF-002: repeated string concatenation inside a loop.
pub(crate) fn detect_perf_2(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let text = assignment.text.as_ref();
        let expr = assignment.expr.as_ref();
        let is_concat = text.contains(" += ")
            || text.contains("= s +")
            || expr.contains("s = s +");
        if !is_concat {
            continue;
        }
        if text.contains("strings.Builder")
            || text.contains("bytes.Buffer")
            || text.contains("strings.Join(")
        {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_2,
            file,
            line,
            col,
            "string is built by repeated concatenation inside a loop body",
            out,
        );
    }
}

/// PERF-003: slice rebuilt inside a loop (e.g. loop-local `make([]T, 0)`).
pub(crate) fn detect_perf_3(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !expr.contains("make([]") || !expr.contains(',') {
            continue;
        }
        if expr.contains(", 0, ") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_3,
            file,
            line,
            col,
            "working slice is rebuilt with make inside a loop body",
            out,
        );
    }
}

/// PERF-004: map allocation inside a loop.
pub(crate) fn detect_perf_4(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !expr.contains("make(map[") {
            continue;
        }
        // `make(map[K]V, hint)` — pre-sized allocation is fine.
        if let Some(close) = expr.find(']') {
            if expr[close..].contains(',') {
                continue;
            }
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_4,
            file,
            line,
            col,
            "map is allocated with make inside a loop body",
            out,
        );
    }
}

/// PERF-005: json.Marshal / Unmarshal / NewEncoder / NewDecoder in a hot loop.
pub(crate) fn detect_perf_5(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(
            call.callee.as_ref(),
            "json.Marshal" | "json.Unmarshal" | "json.NewEncoder" | "json.NewDecoder"
        ) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_5,
            file,
            line,
            col,
            "JSON conversion is performed inside a loop body",
            out,
        );
    }
}

/// PERF-006: fmt.Sprintf / fmt.Fprintf used as repeated string construction
/// inside a loop.
pub(crate) fn detect_perf_6(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "fmt.Sprintf" | "fmt.Fprintf") {
            continue;
        }
        if call.callee.as_ref() == "fmt.Fprintf" && call.arguments.len() >= 2 {
            let first = call.arguments[0].as_ref();
            if first == "&buf" || first == "buf" {
                continue;
            }
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_6,
            file,
            line,
            col,
            "fmt-based formatting is performed inside a loop body",
            out,
        );
    }
}

/// PERF-007: defer inside a loop body.
pub(crate) fn detect_perf_7(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    walk_nodes(
        unit.tree.root_node(),
        &["defer_statement"],
        &mut |node| {
            if nearest_loop(node, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_7,
                file,
                line,
                col,
                "defer statement is placed inside a loop body",
                out,
            );
        },
    );
}

/// PERF-008: time.Parse / time.ParseInLocation inside a loop body.
pub(crate) fn detect_perf_8(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(
            call.callee.as_ref(),
            "time.Parse" | "time.ParseInLocation"
        ) {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let layout = call.arguments[0].as_ref();
        let is_literal = layout.starts_with('"') && layout.ends_with('"');
        if !is_literal {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_8,
            file,
            line,
            col,
            "time.Parse is called inside a loop body with a literal layout",
            out,
        );
    }
}

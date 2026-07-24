use super::super::super::common::is_assignment_in_loop;
use super::super::super::facts::{GoPerfFacts, VarKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{ControlFlowKind, DetectorEvidence, Finding, LineCol, emit};

/// PERF-001: regexp.MustCompile / regexp.Compile inside a loop.
pub(crate) fn detect_perf_1(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !super::super::super::common::is_in_loop(call) {
            continue;
        }
        if !matches!(
            call.callee.as_ref(),
            "regexp.MustCompile" | "regexp.Compile"
        ) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding_with_evidence(
            &META_PERF_1,
            file,
            line,
            col,
            "regular expression compiled inside loop body",
            DetectorEvidence::ControlFlowIssue {
                control_flow_kind: ControlFlowKind::LoopBodyAllocation,
                location: LineCol { line, column: col },
            },
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
        let is_concat = text.contains(" += ") || text.contains("= s +") || expr.contains("s = s +");
        if !is_concat {
            continue;
        }
        if text.contains("strings.Builder")
            || text.contains("bytes.Buffer")
            || text.contains("strings.Join(")
        {
            continue;
        }
        // Suppress when the LHS is known to be a numeric accumulator
        // (e.g. `totalDur := 0.0` + `totalDur += d`). The +=-on-numeric
        // pattern is idiomatic and not a string-concatenation smell.
        if let Some(&kind) = facts.var_kinds.get(assignment.name.as_ref())
            && kind == VarKind::Numeric
        {
            continue;
        }
        // Suppress when the LHS type is unknown and no string literal
        // appears on the RHS — likely a numeric or time.Duration accumulator
        // rather than a string-concatenation pattern.
        let is_known_string = facts
            .var_kinds
            .get(assignment.name.as_ref())
            .map(|k| *k == VarKind::String)
            .unwrap_or(false);
        let has_string_literal = text.contains('"') || text.contains('`');
        if !is_known_string && !has_string_literal {
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
        if let Some(close) = expr.find(']')
            && expr[close..].contains(',')
        {
            continue;
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
        if !super::super::super::common::is_in_loop(call) {
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

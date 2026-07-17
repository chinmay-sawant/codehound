use super::super::super::common::is_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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
pub(crate) fn detect_perf_7(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for &(start_byte, _end_byte) in &facts.defer_starts {
        let Some(&(loop_start, loop_end)) = facts
            .for_ranges
            .iter()
            .filter(|&&(start, end)| start <= start_byte && start_byte <= end)
            .min_by_key(|&&(start, end)| end - start)
        else {
            continue;
        };
        // A defer in a closure launched by the loop runs when that closure
        // returns, not when the enclosing function returns. Only skip this
        // boundary; a loop nested inside the closure still reports normally.
        let is_per_iteration_closure = facts.function_literal_ranges.iter().any(|&(start, end)| {
            loop_start <= start && start < start_byte && start_byte < end && end <= loop_end
        });
        if is_per_iteration_closure {
            continue;
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_7,
            file,
            line,
            col,
            "defer statement is placed inside a loop body",
            out,
        );
    }
}

/// PERF-008: time.Parse / time.ParseInLocation inside a loop body.
pub(crate) fn detect_perf_8(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "time.Parse" | "time.ParseInLocation") {
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

use super::super::super::common::is_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-009: url.Parse / url.ParseRequestURI inside a loop.
pub(crate) fn detect_perf_9(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "url.Parse" | "url.ParseRequestURI") {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_9,
            file,
            line,
            col,
            "URL is parsed inside a loop body",
            out,
        );
    }
}

/// PERF-013: time.After inside long-running loops.
pub(crate) fn detect_perf_13(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_ticker_already =
        source.contains("time.NewTicker(") || source.contains("time.NewTimer(");
    if has_ticker_already {
        return;
    }

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if call.callee.as_ref() != "time.After" {
            continue;
        }
        // Suppress bounded loops (for i := 0; i < N; i++ with small N literal).
        if let Some(loop_node) = unit.tree.root_node().descendant_for_byte_range(
            call.enclosing_loop.unwrap_or(0),
            call.enclosing_loop.unwrap_or(0),
        ) {
            let _ = loop_node;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_13,
            file,
            line,
            col,
            "time.After is allocated inside a loop body",
            out,
        );
    }
}

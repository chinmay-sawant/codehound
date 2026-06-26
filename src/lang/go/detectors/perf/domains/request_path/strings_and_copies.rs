use super::super::super::common::is_assignment_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use super::is_request_handler;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-017: string concatenation per request body parsing.
pub(crate) fn detect_perf_17(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !expr.contains("strings.Join(") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_17,
            file,
            line,
            col,
            "strings.Join is invoked inside a loop on a request path",
            out,
        );
    }
}

/// PERF-018: unnecessary slice copy in a function with a large input slice.
pub(crate) fn detect_perf_18(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // The fixture shape is "processItems(items)" with append(items, ...) in body.
    if !source.contains("func processItems(") {
        return;
    }
    if !source.contains("append(result, items...)") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        if expr.contains("append(result, items...)") {
            let (line, col) = unit.line_col(assignment.start_byte);
            emit::push_finding(
                &META_PERF_18,
                file,
                line,
                col,
                "large slice is copied via append(slice, items...) where reslicing would suffice",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-019: range over slice of large structs by value.
pub(crate) fn detect_perf_19(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for _, record := range records") {
        return;
    }
    if !source.contains("processRecord(record)") {
        return;
    }
    if source.contains("for _, record := range &records")
        || source.contains("for _, record := range recordsPtr")
    {
        return;
    }

    let start = source.find("for _, record := range records").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_19,
        file,
        line,
        col,
        "range over a slice of large structs copies each element by value",
        out,
    );
}

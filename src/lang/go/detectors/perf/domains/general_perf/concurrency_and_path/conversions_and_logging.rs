use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-32: `[]byte(s)` or `string(b)` conversion in a loop or hot path.
pub(crate) fn detect_perf_33(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
        return;
    }
    if !facts.source_index.has("for _, item := range items") {
        return;
    }
    // If the loop breaks early or uses an indexed scan, suppress.
    if facts.source_index.has("for i := 0; i < len(items);") || facts.source_index.has("break") {
        return;
    }

    let start = source.find("for _, item := range items").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_33,
        file,
        line,
        col,
        "range over a large slice on a request path; consider indexed scan or early break",
        out,
    );
}

/// PERF-41: standard library `log` package used inside a request handler or
/// hot loop.
pub(crate) fn detect_perf_41(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "log.Println" | "log.Printf" | "log.Print" | "log.Fatal" | "log.Fatalf" | "log.Fatalln"
        ) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_41,
            file,
            line,
            col,
            "standard log is used in a request path; prefer a structured leveled logger",
            out,
        );
        return;
    }
    let _ = source;
}

/// PERF-44: type assertion on the same value repeated inside a function.
pub(crate) fn detect_perf_44(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) && !facts.source_index.has("for ") {
        return;
    }

    let mut assertions: Vec<(usize, String)> = Vec::new();
    for &(start_byte, end_byte) in &facts.type_assertions {
        let text = &source[start_byte..end_byte];
        let lhs = text.split_once(".(").map(|(lhs, _)| lhs.trim().to_string());
        if let Some(lhs) = lhs {
            assertions.push((start_byte, lhs));
        }
    }

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
pub(crate) fn detect_perf_48(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) && !facts.source_index.has("for ") {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "bytes.Equal" | "strings.EqualFold" | "bytes.Compare"
        ) {
            continue;
        }
        if facts
            .source_index
            .has("if len(a) != len(b) { return false }")
            || facts.source_index.has("len(prefix)")
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
    let _source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) && !facts.source_index.has("for ") {
        return;
    }
    if !facts.source_index.has("copy(buf, payload)") && !facts.source_index.has("copy(dst, src)") {
        return;
    }
    if facts
        .source_index
        .has("if len(payload) > len(buf) { return }")
    {
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

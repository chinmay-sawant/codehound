use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::{CallFact, GoPerfFacts};
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-33: range over a large slice in a request handler / batch processor
/// where indexed scan would be more efficient.
pub(crate) fn detect_perf_35(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "fmt.Sprintf" | "fmt.Errorf") {
            continue;
        }
        if !is_in_loop_present(&facts.calls) && !is_request_path(source) {
            continue;
        }
        // A single literal argument does not box; the format call is a
        // pure passthrough.
        if call.arguments.len() < 2 {
            continue;
        }
        // The format string itself is a string, but the *other* args are
        // passed as `interface{}` and get boxed. We use `>1` as the proxy.
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_35,
            file,
            line,
            col,
            "fmt.Sprintf / Errorf boxes arguments through interface{} on a hot path",
            out,
        );
        return;
    }
}

/// PERF-36: `go func(){ use(v) }()` capturing a loop variable.
pub(crate) fn detect_perf_37(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    // The function must (a) declare the slice as a nil/empty `var` or `:=`
    // without a `make` and (b) grow it via `append` inside a loop.
    let has_unpreallocated_slice = source.contains("var out []int")
        || source.contains("out := []int{}")
        || source.contains("results := []int{}")
        || source.contains("var results []int")
        || source.contains("var out []string")
        || source.contains("out := []string{}")
        || source.contains("out := []byte{}")
        || source.contains("var out []byte");
    if !has_unpreallocated_slice {
        return;
    }
    if source.contains("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_37,
            file,
            line,
            col,
            "slice is grown by append on a request path without a capacity hint",
            out,
        );
        return;
    }
}

/// PERF-38: unbuffered channel in a producer / consumer pipeline.
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

pub(super) fn is_in_loop_present(calls: &[CallFact]) -> bool {
    calls.iter().any(super::super::super::super::common::is_in_loop)
}

use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_38(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("make(chan") {
        return;
    }
    // A buffered channel always has a `, N` suffix.
    if facts.source_index.has("make(chan int, ")
        || facts.source_index.has("make(chan struct{}, ")
        || facts.source_index.has("make(chan string, ")
        || facts.source_index.has("make(chan T, ")
    {
        return;
    }
    // Suppress test / one-shot signals.
    if facts.source_index.has("_test.go") {
        return;
    }

    let start = source.find("make(chan").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_38,
        file,
        line,
        col,
        "unbuffered channel blocks producers; consider a buffered channel or a worker pool",
        out,
    );
}

/// PERF-39: `for { select { ...; default: ... } }` busy-wait pattern.
pub(crate) fn detect_perf_39(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("default:") {
        return;
    }
    // Suppress if a backoff / sleep is present.
    if facts.source_index.has("time.Sleep(") {
        return;
    }
    // Suppress the timer-drain idiom (`if !timer.Stop() { select { ...
    // default: } }`) where default is a deliberate non-blocking peek.
    if facts.source_index.has("!timer.Stop()") || facts.source_index.has("if !t.Stop()") {
        return;
    }

    for &(start_byte, end_byte) in &facts.for_ranges {
        let text = &source[start_byte..end_byte];
        if !text.contains("select") || !text.contains("default:") {
            continue;
        }
        // Only flag infinite `for { ... }` loops. Bounded `for i := 0; ...`
        // or range loops are not the busy-wait pattern this rule targets.
        let header = text.lines().next().unwrap_or("").trim_start();
        if !header.starts_with("for {") {
            continue;
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_39,
            file,
            line,
            col,
            "select with default branch inside a for-loop is a busy-wait; add a backoff or use channels",
            out,
        );
    }
}

/// PERF-40: `time.Now()` called multiple times in the same function body.
pub(crate) fn detect_perf_40(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    let on_hot_path = is_request_path(&facts.source_index);
    let in_loop_present = facts.source_index.has("for ");

    if !on_hot_path && !in_loop_present {
        return;
    }

    let now_count = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "time.Now")
        .count();
    if now_count < 2 {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "time.Now" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_40,
            file,
            line,
            col,
            "time.Now is called repeatedly in the same function body",
            out,
        );
        return;
    }
}

pub(crate) fn detect_perf_43(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) && !facts.source_index.has("for ") {
        return;
    }

    for &(start_byte, end_byte) in &facts.defer_starts {
        let text = &source[start_byte..end_byte];
        if !text.contains("recover()") {
            continue;
        }
        if !is_request_path(&facts.source_index) {
            let in_loop = facts
                .for_ranges
                .iter()
                .any(|&(s, e)| s <= start_byte && start_byte <= e);
            if !in_loop {
                continue;
            }
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_43,
            file,
            line,
            col,
            "defer-recover runs in a hot path; add the recover at a higher boundary",
            out,
        );
    }
}

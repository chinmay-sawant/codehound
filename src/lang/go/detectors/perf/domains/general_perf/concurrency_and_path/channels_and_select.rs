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
    // Suppress test / one-shot signals.
    if facts.source_index.has("_test.go") {
        return;
    }

    // Report the first unbuffered non-signal channel. Empty `chan struct{}`
    // is the standard done/stop coordination idiom and is not a pipeline
    // producer/consumer buffer smell.
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("make(chan") {
        let start = search + rel;
        let after = &source[start + "make(chan".len()..];
        let after = after.trim_start();
        // Buffered: make(chan T, N) — skip this call.
        if let Some(comma_rel) = after.find(',') {
            let close_rel = after.find(')');
            if close_rel.is_some_and(|c| c > comma_rel) {
                // Confirm the comma is at the top level of the make args
                // (not inside a nested type). Empty struct{} has no nested
                // commas before the element-type close.
                let between = after[..comma_rel].trim();
                if !between.is_empty() {
                    search = start + "make(chan".len();
                    continue;
                }
            }
        }
        // Unbuffered empty-struct signal channel: make(chan struct{})
        let trimmed = after.trim_start();
        if let Some(rest) = trimmed.strip_prefix("struct{}") {
            if rest.trim_start().starts_with(')') {
                search = start + "make(chan".len();
                continue;
            }
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_38,
            file,
            line,
            col,
            "unbuffered channel blocks producers; consider a buffered channel or a worker pool",
            out,
        );
        return;
    }
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
    use crate::lang::go::detectors::perf::common::enclosing_function_name;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let on_hot_path = is_request_path(&facts.source_index);
    let in_loop_present = facts.source_index.has("for ");

    if !on_hot_path && !in_loop_present {
        return;
    }

    // Count per enclosing function — separate helpers each calling Now once
    // are not the repeated-sample smell this rule targets.
    let mut by_func: Vec<(Option<&str>, Vec<usize>)> = Vec::new();
    for call in &facts.calls {
        if call.callee.as_ref() != "time.Now" {
            continue;
        }
        let fname = enclosing_function_name(source, call.start_byte);
        if let Some(entry) = by_func.iter_mut().find(|(n, _)| *n == fname) {
            entry.1.push(call.start_byte);
        } else {
            by_func.push((fname, vec![call.start_byte]));
        }
    }

    for (_fname, sites) in by_func {
        if sites.len() < 2 {
            continue;
        }
        let (line, col) = unit.line_col(sites[0]);
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

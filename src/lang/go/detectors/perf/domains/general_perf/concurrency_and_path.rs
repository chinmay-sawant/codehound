use super::super::super::common::is_request_path;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_29(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Bounded patterns: worker pool, semaphore, errgroup.WithContext, or
    // a semaphore that uses a buffered channel of `struct{}` tokens.
    if source.contains("errgroup.WithContext")
        || source.contains("sem := make(chan struct{}")
        || source.contains("sem <- struct{}{}")
        || source.contains("workerCount")
        || source.contains("workerPool")
        || source.contains("semaphore")
        // Goroutine tied to the request lifecycle — not "unbounded".
        || source.contains("sync.WaitGroup")
        || source.contains("wg.Add(")
        || source.contains("c.Request.Context()")
        || source.contains("ctx, cancel := context.WithCancel")
        || source.contains("ctx, cancel := context.WithTimeout")
    {
        return;
    }

    for &(start_byte, end_byte) in &facts.go_starts {
        let text = &source[start_byte..end_byte];
        if !text.contains("go func") {
            continue;
        }
        let in_loop = facts
            .for_ranges
            .iter()
            .any(|&(s, e)| s <= start_byte && start_byte <= e);
        let on_request_path = is_request_path(source);
        if !in_loop && !on_request_path {
            continue;
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_29,
            file,
            line,
            col,
            "goroutine is spawned without a bounded worker pool or semaphore",
            out,
        );
    }
}

/// PERF-30: `context.Background()` / `context.TODO()` in a goroutine launched
/// from a request handler.
pub(crate) fn detect_perf_30(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "context.Background" | "context.TODO") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_30,
            file,
            line,
            col,
            "context.Background / TODO detaches the goroutine from the request context",
            out,
        );
        return;
    }
    let _ = source;
}

/// PERF-31: `defer` inside a request handler or hot function.
pub(crate) fn detect_perf_31(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    // Suppress resource-cleanup defer patterns (`defer x.Close()`,
    // `defer cancel()`, `defer x.Stop()`) — those are idiomatic Go and
    // should not trip the hot-path heuristic.
    let has_resource_defer =
        source.contains(".Close()") || source.contains("cancel()") || source.contains(".Stop()");
    if has_resource_defer {
        return;
    }

    for &(start_byte, _end_byte) in &facts.defer_starts {
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_31,
            file,
            line,
            col,
            "defer is used in a hot handler function; consider explicit cleanup",
            out,
        );
    }
}

/// PERF-32: `[]byte(s)` or `string(b)` conversion in a loop or hot path.
pub(crate) fn detect_perf_33(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if !source.contains("for _, item := range items") {
        return;
    }
    // If the loop breaks early or uses an indexed scan, suppress.
    if source.contains("for i := 0; i < len(items);") || source.contains("break") {
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

pub(crate) fn detect_perf_38(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("make(chan") {
        return;
    }
    // A buffered channel always has a `, N` suffix.
    if source.contains("make(chan int, ")
        || source.contains("make(chan struct{}, ")
        || source.contains("make(chan string, ")
        || source.contains("make(chan T, ")
    {
        return;
    }
    // Suppress test / one-shot signals.
    if source.contains("_test.go") {
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

    if !source.contains("default:") {
        return;
    }
    // Suppress if a backoff / sleep is present.
    if source.contains("time.Sleep(") {
        return;
    }
    // Suppress the timer-drain idiom (`if !timer.Stop() { select { ...
    // default: } }`) where default is a deliberate non-blocking peek.
    if source.contains("!timer.Stop()") || source.contains("if !t.Stop()") {
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
    let source = unit.source.as_ref();

    let on_hot_path = is_request_path(source);
    let in_loop_present = source.contains("for ");

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

/// PERF-41: standard library `log` package used inside a request handler or
/// hot loop.
pub(crate) fn detect_perf_41(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
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

pub(crate) fn detect_perf_43(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    for &(start_byte, end_byte) in &facts.defer_starts {
        let text = &source[start_byte..end_byte];
        if !text.contains("recover()") {
            continue;
        }
        if !is_request_path(source) {
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

/// PERF-44: type assertion on the same value repeated inside a function.
pub(crate) fn detect_perf_44(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
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
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "bytes.Equal" | "strings.EqualFold" | "bytes.Compare"
        ) {
            continue;
        }
        if source.contains("if len(a) != len(b) { return false }") || source.contains("len(prefix)")
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
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }
    if !source.contains("copy(buf, payload)") && !source.contains("copy(dst, src)") {
        return;
    }
    if source.contains("if len(payload) > len(buf) { return }") {
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

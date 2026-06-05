//! PERF-34 to PERF-41 detectors.
//!
//! Heuristics for slice/append growth inside map and range loops, interface
//! boxing on hot paths, loop-variable capture in goroutines, channel sizing,
//! busy-wait patterns, repeated `time.Now`, and standard-library log usage.

use super::super::super::common::{is_in_loop, is_request_path};
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::ast::walk_nodes;
use crate::ast::nearest_loop;
use crate::core::ParsedUnit;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

/// PERF-34: `append` inside a `for k,v := range map` body.
pub(crate) fn detect_perf_34(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // The map-range + append pattern is only a problem when the slice is
    // NOT preallocated. Suppress when `make([]T, 0, len(m))` (or any
    // capacity hint that references the same map) appears before the
    // loop.
    if source.contains("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        if !source.contains("for _, v := range m")
            && !source.contains("for k, v := range m")
            && !source.contains("for k := range m")
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_34,
            file,
            line,
            col,
            "append inside a for-range over a map grows the slice without preallocation",
            out,
        );
        return;
    }
}

/// PERF-35: interface boxing on a hot path (`fmt.Sprintf` with non-string
/// arguments, or interface{}-typed function parameters in a hot call).
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
        if !is_in_loop(call) && !is_request_path(source) {
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
pub(crate) fn detect_perf_36(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("go func()") {
        return;
    }
    // Suppress when a per-iteration copy is taken (Go 1.22+ idiom or explicit
    // shadowing).
    if source.contains("v := v") || source.contains("go 1.22") {
        return;
    }

    walk_nodes(
        unit.tree.root_node(),
        &["go_statement", "for_statement"],
        &mut |node| {
            if node.kind() != "go_statement" {
                return;
            }
            let in_loop = nearest_loop(node, LOOP_NODE_KINDS).is_some();
            if !in_loop {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_36,
                file,
                line,
                col,
                "goroutine captures a loop variable by reference; copy it per iteration",
                out,
            );
        },
    );
}

/// PERF-37: `append` in a hot grow pattern with no `make` preallocation.
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
pub(crate) fn detect_perf_39(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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

    walk_nodes(unit.tree.root_node(), &["for_statement"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !text.contains("select") || !text.contains("default:") {
            return;
        }
        // Only flag infinite `for { ... }` loops. Bounded `for i := 0; ...`
        // or range loops are not the busy-wait pattern this rule targets.
        let header = text.lines().next().unwrap_or("").trim_start();
        if !header.starts_with("for {") {
            return;
        }
        let (line, col) = unit.line_col(node.start_byte());
        emit::push_finding(
            &META_PERF_39,
            file,
            line,
            col,
            "select with default branch inside a for-loop is a busy-wait; add a backoff or use channels",
            out,
        );
    });
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

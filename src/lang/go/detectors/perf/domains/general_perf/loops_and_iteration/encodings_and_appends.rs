use super::super::super::super::common::is_in_loop;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::ast::nearest_loop;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_26(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(
            call.callee.as_ref(),
            "base64.StdEncoding.EncodeToString"
                | "base64.StdEncoding.DecodeString"
                | "base64.URLEncoding.EncodeToString"
                | "base64.URLEncoding.DecodeString"
                | "base64.RawStdEncoding.EncodeToString"
                | "base64.RawStdEncoding.DecodeString"
                | "base64.NewEncoder"
                | "base64.NewDecoder"
        ) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_26,
            file,
            line,
            col,
            "base64 encoding or decoding is performed inside a loop body",
            out,
        );
    }
}

/// PERF-27: short-lived buffer / struct allocations on hot paths that should
/// be wrapped in a `sync.Pool`.
pub(crate) fn detect_perf_34(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    // The map-range + append pattern is only a problem when the slice is
    // NOT preallocated. Suppress when `make([]T, 0, len(m))` (or any
    // capacity hint that references the same map) appears before the
    // loop.
    if facts.source_index.has("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        if !facts.source_index.has("for _, v := range m")
            && !facts.source_index.has("for k, v := range m")
            && !facts.source_index.has("for k := range m")
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
pub(crate) fn detect_perf_36(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !facts.source_index.has("go func()") {
        return;
    }
    // Suppress when a per-iteration copy is taken (Go 1.22+ idiom or explicit
    // shadowing).
    if facts.source_index.has("v := v") || facts.source_index.has("go 1.22") {
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
pub(crate) fn detect_perf_45(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !facts.source_index.has("for _, v := range") && !facts.source_index.has("for i := 0;") {
        return;
    }
    if facts.source_index.has("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_45,
            file,
            line,
            col,
            "append inside a loop without a capacity hint causes repeated reallocation",
            out,
        );
        return;
    }
}

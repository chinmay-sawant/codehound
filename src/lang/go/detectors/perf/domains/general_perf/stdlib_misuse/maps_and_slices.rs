//! PERF-106, 110, 123, 128, 129, 192: maps, slices, and sync.Pool.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::{CallFact, GoPerfFacts};
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{emit, Finding};
use super::common::{is_simple_ident, method_name};
use super::ranges_and_types::word_appears_in;
use super::strings_bytes::{intermediate, intervening_read};

/// PERF-106: `sync.Map` used in a write-heavy workload. We count
/// `Store` and `LoadAndDelete` calls vs `Load` calls in the file and
/// flag when writes strictly outnumber reads.
pub(crate) fn detect_perf_106(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("sync.Map") {
        return;
    }

    let mut writes = 0usize;
    let mut reads = 0usize;
    for call in &facts.calls {
        let method = method_name(call.callee.as_ref());
        match method {
            "Store" | "Swap" | "LoadAndDelete" | "Delete" | "CompareAndSwap"
            | "CompareAndDelete" => {
                writes += 1;
            }
            "Load" | "LoadOrStore" | "Range" => {
                reads += 1;
            }
            _ => {}
        }
    }
    // Need at least one read for the count to be meaningful and
    // writes must strictly outnumber reads.
    if reads == 0 || writes <= reads {
        return;
    }
    let (line, col) = sync_map_location(source, unit);
    emit::push_finding(
        &META_PERF_106,
        file,
        line,
        col,
        "sync.Map is write-heavy; use a plain map guarded by sync.Mutex instead",
        out,
    );
}

fn sync_map_location(source: &str, unit: &ParsedUnit) -> (usize, usize) {
    // The finding should point at the `sync.Map` declaration, not
    // at any call site.
    let byte = source.find("sync.Map").unwrap_or(0);
    unit.line_col(byte)
}

/// PERF-110: `sync.Pool` whose `New` function returns a value type
/// instead of a pointer. Each `Put` boxes the value into an `eface`
/// on the pool's internal queue, and each `Get` unboxes it; returning
/// `*T` from `New` avoids the round trip.
pub(crate) fn detect_perf_110(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    use crate::ast::walk_nodes;
    use tree_sitter::Node;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("sync.Pool") {
        return;
    }

    // Walk composite-literal nodes whose text starts with `sync.Pool{`.
    // We need the literal's full text to inspect the `New:` field.
    walk_nodes(
        unit.tree.root_node(),
        &["composite_literal"],
        &mut |node: Node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            if !text.starts_with("sync.Pool{") {
                return;
            }
            // Find the New: ... } body. We bound the search to the
            // literal's text; `New:` is the only field we care about.
            let Some(new_idx) = text.find("New:") else {
                return;
            };
            let after = &text[new_idx..];
            // The New field is a function literal; we don't try to
            // walk it as AST (the value is a `func_literal` inside a
            // keyed_element). Just inspect the function literal text.
            // Detect: `func() *T {` (good) vs `func() T {` (bad) or
            // `func() interface{} { return &T{} }` (good).
            if let Some(open) = after.find("func()") {
                let sig = &after[open..];
                // The signature ends at the next `{`.
                let sig_end = sig.find('{').unwrap_or(sig.len());
                let signature = &sig[..sig_end];
                // Reject when the signature itself returns a pointer
                // (e.g. `func() *Foo { ... }`).
                if signature.contains('*') {
                    return;
                }
                // The return type is the trailing identifier in
                // `func() T`. Reject if it starts with `*`.
                let return_type = signature
                    .trim_start_matches("func()")
                    .trim()
                    .trim_start_matches('*')
                    .trim();
                if return_type.is_empty() || return_type == "_" {
                    return;
                }
                // If the body actually returns a pointer (`return &T{...}`
                // or `return new(T)`), the function is fine.
                if let Some(ret_idx) = after.find("return") {
                    let after_ret = &after[ret_idx + "return".len()..];
                    if after_ret.trim_start().starts_with('&')
                        || after_ret.trim_start().starts_with("new(")
                    {
                        return;
                    }
                }
                // The return type looks like a value type and the
                // return value is not a pointer — flag.
                let (line, col) = unit.line_col(node.start_byte());
                emit::push_finding(
                    &META_PERF_110,
                    file,
                    line,
                    col,
                    "sync.Pool New returns a value type; return a pointer (e.g. *Foo) to avoid boxing on Put",
                    out,
                );
            }
        },
    );
}

/// PERF-123: `make(T, 0)` or `make(T, 0, 0)` where the zero length is
/// redundant. Pre-allocated buffers like `make([]byte, 0, cap)` are
/// intentionally allowed.
pub(crate) fn detect_perf_123(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        // make(T) has no length arg; make(T, N) has one; make(T, N, M) has two.
        let args = &call.arguments;
        if args.len() < 2 {
            continue;
        }
        if args[1].as_ref() != "0" {
            continue;
        }
        // Allow make(T, 0, cap) where cap > 0.
        if args.len() == 3 && args[2].as_ref() != "0" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_123,
            file,
            line,
            col,
            "make with explicit zero length/capacity is redundant; omit the zero argument",
            out,
        );
    }
}

/// PERF-128: three or more consecutive `append` calls to the same
/// slice without intervening reads. This is the stricter version of
/// PERF-119 (which catches 2+); three independent growths is a
/// stronger signal of accidental reallocation.
pub(crate) fn detect_perf_128(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut appends: Vec<&CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "append")
        .collect();
    if appends.len() < 3 {
        return;
    }
    appends.sort_by_key(|c| c.start_byte);

    for triple in appends.windows(3) {
        let a = triple[0];
        let b = triple[1];
        let c = triple[2];
        if a.arguments.is_empty() || b.arguments.is_empty() || c.arguments.is_empty() {
            continue;
        }
        let target = a.arguments[0].as_ref();
        if b.arguments[0].as_ref() != target || c.arguments[0].as_ref() != target {
            continue;
        }
        // No intervening reads between the first and last call.
        if intervening_read(&unit.source[intermediate(a, b)..b.start_byte], target) {
            continue;
        }
        if intervening_read(&unit.source[intermediate(b, c)..c.start_byte], target) {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_128,
            file,
            line,
            col,
            "three or more independent append calls can be combined into one variadic append",
            out,
        );
        return;
    }
}

/// PERF-129: `for _, v := range xs` where `v` is never used in the
/// loop body copies each element unnecessarily. Range by index when
/// the value is unused: `for i := range xs`.
pub(crate) fn detect_perf_129(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for (start, end) in &facts.for_ranges {
        let range_text = &source[*start..*end];
        let Some(body_start) = range_text.find('{') else {
            continue;
        };
        let head = &range_text[..body_start];
        let after_for = head.trim_start_matches("for").trim_start();
        let Some((bindings, _iter)) = after_for.split_once("range") else {
            continue;
        };
        let bindings = bindings
            .split_once(":=")
            .map(|(b, _)| b)
            .unwrap_or(bindings);
        let mut parts = bindings.split(',');
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };
        if parts.next().is_some() {
            continue;
        }
        let key = key.trim();
        let val = val.trim();
        if key != "_" {
            continue;
        }
        if val.is_empty() || val == "_" || !is_simple_ident(val) {
            continue;
        }
        let body = &range_text[body_start..];
        if word_appears_in(body, val) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_129,
            file,
            line,
            col,
            "range loop copies the value but the value is unused; range by index instead",
            out,
        );
    }
}

/// PERF-192: `make(map[K]V)` without a size hint. When the entries
/// are loaded from a slice with a known length, the map will resize
/// as it grows; pass `len(src)` as the hint.
pub(crate) fn detect_perf_192(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        let args = &call.arguments;
        if args.len() != 1 {
            continue;
        }
        let first = args[0].as_ref();
        if !first.starts_with("map[") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_192,
            file,
            line,
            col,
            "make(map[K]V) without a size hint; pass len(src) to avoid map growth",
            out,
        );
    }
    let _ = facts;
}

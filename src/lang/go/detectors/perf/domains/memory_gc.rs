//! Migrated from hot_path_misc.rs: domain-specific Memory/GC PERF detectors.
//!
//! PERF-134, PERF-138, PERF-139, PERF-150, PERF-151, PERF-169, PERF-191

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{
    char_boundary, file_has_handler, is_handler_shaped, is_in_loop,
};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_134(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    if !source.contains("for ") {
        return;
    }
    // Look for a `for` block containing both `Read(buf)` and
    // `Write(buf[:` — the manual-copy idiom.
    if !source.contains(".Read(") || !source.contains(".Write(") {
        return;
    }
    // Simple presence: any `.Read(buf)` paired with `.Write(buf[:`
    // in a file with a `for` loop is almost certainly the manual
    // copy pattern. We use `buf` as the canonical variable name.
    if source.contains("Read(buf") && source.contains("Write(buf[:") {
        let pos = source.find("Read(buf").unwrap_or(0);
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_134,
            file,
            line,
            col,
            "manual io.Read + io.Write loop; use io.Copy(dst, src) instead",
            out,
        );
    }
}

pub(crate) fn detect_perf_138(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.Stack" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_138,
            file,
            line,
            col,
            "runtime.Stack on a hot path; capture the stack lazily (debug builds only) or use a pre-built constant",
            out,
        );
    }
}

pub(crate) fn detect_perf_139(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // A closure in a handler that captures outer scope variables
    // is the escape pattern. We look for `go func(` or `defer func(`
    // that accesses a local variable (not just its parameters).
    if !source.contains("go func(") && !source.contains("defer func(") {
        return;
    }
    // The closure must capture an outer variable: look for
    // `.Write` inside the closure body. We scan for `go func(`
    // or `defer func(` and check if `.Write(` appears between
    // the `{` that opens the closure body and the `})` that
    // closes it (or the next `)(` for defer func() calls).
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Write") {
            continue;
        }
        // Check if this Write is inside a closure by finding a
        // `go func(` that starts before it and whose matching
        // `})` comes after it.
        // Find the LAST `go func(` before the Write call
        let search_start = call.start_byte.saturating_sub(1000);
        let search_region = &source[char_boundary(source, search_start)..call.start_byte];
        let last_go_rel = search_region.rfind("go func(");
        let last_defer_rel = search_region.rfind("defer func(");
        let closure_start_rel = match (last_go_rel, last_defer_rel) {
            (Some(g), Some(d)) => Some(g.max(d)),
            (Some(g), None) => Some(g),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        let Some(csr) = closure_start_rel else {
            continue;
        };
        // Convert relative offset to absolute source offset
        let cs = search_start + csr;
        // The closure body starts at the `{` after `go func()`
        // or `defer func()`. We find the next `{` after cs.
        // Look forward from cs for the first `{`.
        let after_closure_open = &source[cs..];
        let body_open = match after_closure_open.find('{') {
            Some(p) => cs + p,
            None => continue,
        };
        // Look for `})` or `}()` that closes this closure.
        let after_body = &source[body_open..];
        let close_pos = after_body
            .find("})")
            .or_else(|| after_body.find("}()"))
            .or_else(|| after_body.find("}"))
            .map(|p| body_open + p);
        let Some(cp) = close_pos else {
            continue;
        };
        // The Write call must be between body_open and cp
        if call.start_byte > body_open && call.start_byte < cp {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_139,
                file,
                line,
                col,
                "closure in hot-path handler captures outer variables; consider extracting to a named function",
                out,
            );
            return;
        }
    }
}

pub(crate) fn detect_perf_150(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // Heuristic: count large local allocations.
    // We look for `[N]byte` array declarations, `make([]byte,N)`
    // where N >= 1024, and lines with large string literals.
    let large_array = source.matches("[1024]byte").count()
        + source.matches("[2048]byte").count()
        + source.matches("[4096]byte").count()
        + source.matches("[8192]byte").count()
        + source.matches("[16384]byte").count()
        + source.matches("[32768]byte").count()
        + source.matches("[65536]byte").count();
    // ponytail: still misses non-power-of-2 sizes; switch to regex capture if
    // we need to catch e.g. [3072]byte in real code.
    let make_big = source.matches("make([]byte, 1024)").count()
        + source.matches("make([]byte, 2048)").count()
        + source.matches("make([]byte, 4096)").count()
        + source.matches("make([]byte, 8192)").count()
        + source.matches("make([]byte, 16384)").count();
    let large_strings = source
        .lines()
        .filter(|l| l.len() > 200 && l.contains('"'))
        .count();

    let total = large_array + make_big + large_strings;
    if total >= 2 {
        let pos = source.find("]byte").unwrap_or_else(|| {
            source
                .find("make([]byte,")
                .unwrap_or(source.find('"').unwrap_or(0))
        });
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_150,
            file,
            line,
            col,
            "large stack frame: multiple large local allocations (> 1 KiB); consider heap-allocating or reducing buffer sizes",
            out,
        );
    }
}

pub(crate) fn detect_perf_151(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // Heuristic: a function that has both `for` AND `switch` AND
    // `defer func` is complex enough that the compiler won't inline
    // it. We also flag functions with > 40 source lines between
    // `func` and the matching `}`.
    let has_loop = source.contains("for ");
    let has_switch = source.contains("switch ");
    let has_closure = source.contains("func(") || source.contains("go ");

    // Count approximate lines in the first function body.
    let func_lines = source
        .lines()
        .skip_while(|l| !l.contains("func "))
        .take_while(|l| !l.trim().is_empty())
        .count();

    let complex = (has_loop && has_switch) || func_lines > 50;
    if complex && has_closure {
        let pos = source.find("func ").unwrap_or(0);
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_151,
            file,
            line,
            col,
            "non-inlinable handler function: too complex for the Go compiler to inline; reduce body size or split into smaller functions",
            out,
        );
    }
}

pub(crate) fn detect_perf_169(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        // Match `x.Store` and `atomic.Value.Store` shapes.
        if !callee.ends_with(".Store") {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        // The detector should only fire when the file uses
        // `sync/atomic` (otherwise `.Store` could be on a map,
        // channel, etc., which are different rules).
        if !facts.source_index.has("sync/atomic") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_169,
            file,
            line,
            col,
            "atomic.Value.Store inside a loop allocates an interface{} per call; use atomic.Pointer[T] (Go 1.19+) for frequent updates",
            out,
        );
        return;
    }
}

pub(crate) fn detect_perf_191(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Suppress when the file uses protobuf or similar
    // frameworks that prefer pointer types.
    if source.contains("proto.") || source.contains("protobuf") {
        return;
    }

    // Heuristic: a slice literal or declaration of `[]*T` where
    // the type T is declared with 1 or 2 fields.
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("[]*") {
        let pos = search_from + rel;
        let after = &source[pos + 3..char_boundary(source, (pos + 128).min(source.len()))];
        let type_name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if type_name.is_empty() {
            search_from = pos + 3;
            continue;
        }
        let pattern = format!("type {type_name} struct");
        if let Some(struct_start) = source.find(&pattern)
            && let Some(open) = source[struct_start..].find('{')
        {
            let body_start = struct_start + open + 1;
            if let Some(close_rel) = source[body_start..].find('}') {
                let body = &source[body_start..body_start + close_rel];
                let field_count = body
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| {
                        !l.is_empty()
                            && !l.starts_with("//")
                            && !l.starts_with('{')
                            && !l.starts_with('}')
                            && !l.starts_with('`')
                    })
                    .count();
                if field_count > 0 && field_count <= 2 {
                    let (line, col) = unit.line_col(pos);
                    emit::push_finding(
                        &META_PERF_191,
                        file,
                        line,
                        col,
                        "slice of pointers to a small struct; use []T (value type) to avoid per-element heap allocations",
                        out,
                    );
                    return;
                }
            }
        }
        search_from = pos + 3;
    }
}

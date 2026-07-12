use super::super::super::super::common::{is_assignment_in_loop, is_hot_path, is_request_path};
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_27(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if facts.source_index.has("sync.Pool") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        // `bytes.Buffer{}` / `new(bytes.Buffer)` / `strings.Builder{}` are
        // short-lived buffers that should often be pooled on hot paths.
        // Large `make([]byte, N)` (N ≥ 4KiB) inside a loop is also a pool miss.
        let is_buffer = expr.contains("bytes.Buffer{")
            || expr.contains("new(bytes.Buffer)")
            || expr.contains("strings.Builder{");
        let large_make = large_make_byte_slice(expr);
        if !is_buffer && !large_make {
            continue;
        }
        // Large make[]byte only when inside a loop (one-shot large buffers are fine).
        let in_loop = is_assignment_in_loop(assignment);
        if large_make && !in_loop {
            continue;
        }
        if !is_hot_path(source, assignment.start_byte, &facts.source_index, in_loop) {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        let msg = if expr.contains("strings.Builder") {
            "strings.Builder is allocated on a hot path; pool it via sync.Pool or hoist + Reset"
        } else if large_make {
            "large []byte is make'd inside a loop; pool and reuse or hoist the buffer"
        } else {
            "bytes.Buffer is allocated on a hot path; pool it via sync.Pool"
        };
        emit::push_finding(&META_PERF_27, file, line, col, msg, out);
        return;
    }
}

/// `make([]byte, N)` / `make([]byte, 0, N)` with integer literal N ≥ 4096.
fn large_make_byte_slice(expr: &str) -> bool {
    let expr = expr.trim();
    let rest = if let Some(r) = expr.strip_prefix("make([]byte,") {
        r
    } else if let Some(r) = expr.strip_prefix("make([]uint8,") {
        r
    } else {
        return false;
    };
    let rest = rest.trim_start();
    // Forms: `8192)`, `0, 8192)`, `len(...` — only literal sizes.
    let nums: Vec<u64> = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    // Prefer the capacity/length literal that is ≥ 4096.
    nums.iter().any(|&n| n >= 4096)
}

/// PERF-43: `defer func(){ recover() }()` in a hot loop or per-request path.
pub(crate) fn detect_perf_46(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "strings.TrimSpace"
                | "strings.Trim"
                | "strings.TrimPrefix"
                | "strings.TrimSuffix"
                | "strings.TrimLeft"
                | "strings.TrimRight"
        ) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_46,
            file,
            line,
            col,
            "string trimming allocates on a request path; check the need first",
            out,
        );
        return;
    }
}

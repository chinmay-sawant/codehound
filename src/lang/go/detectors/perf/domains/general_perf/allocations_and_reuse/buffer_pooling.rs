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
        // `make([]byte, …)` stays out — sized scanners/reads are fine.
        let is_poolable = expr.contains("bytes.Buffer{")
            || expr.contains("new(bytes.Buffer)")
            || expr.contains("strings.Builder{");
        if !is_poolable {
            continue;
        }
        if !is_hot_path(
            source,
            assignment.start_byte,
            &facts.source_index,
            is_assignment_in_loop(assignment),
        ) {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        let msg = if expr.contains("strings.Builder") {
            "strings.Builder is allocated on a hot path; pool it via sync.Pool or hoist + Reset"
        } else {
            "bytes.Buffer is allocated on a hot path; pool it via sync.Pool"
        };
        emit::push_finding(&META_PERF_27, file, line, col, msg, out);
        return;
    }
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

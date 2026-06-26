use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_27(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if source.contains("sync.Pool") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        // `bytes.Buffer{}` / `new(bytes.Buffer)` are pure per-request
        // allocations that should be pooled. `make([]byte, …)` is too noisy
        // — sized buffers for scanners / reads are fine.
        let is_poolable = expr.contains("bytes.Buffer{")
            || expr.contains("new(bytes.Buffer)")
            || expr.contains("bytes.Buffer{}");
        if !is_poolable {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_27,
            file,
            line,
            col,
            "bytes.Buffer is allocated per request; pool it via sync.Pool",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-43: `defer func(){ recover() }()` in a hot loop or per-request path.
pub(crate) fn detect_perf_46(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
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
    let _ = source;
}

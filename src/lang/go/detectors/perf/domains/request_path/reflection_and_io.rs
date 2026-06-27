use super::super::super::common::is_assignment_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use super::is_request_handler;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-020: reflect.ValueOf / reflect.TypeOf / reflect.New on a hot path.
pub(crate) fn detect_perf_20(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_handler(&facts.source_index) {
        return;
    }

    let index_triggers = ["reflect.ValueOf(", "reflect.TypeOf(", "reflect.New("];
    let callee_triggers = ["reflect.ValueOf", "reflect.TypeOf", "reflect.New"];
    if !facts.source_index.has_any(&index_triggers) {
        return;
    }
    if facts.source_index.has("// reflection initialised at startup") {
        return;
    }

    for call in &facts.calls {
        if !callee_triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_20,
            file,
            line,
            col,
            "reflect is invoked on a request path; cache reflect.Type or Value at startup",
            out,
        );
        return;
    }
}

/// PERF-021: io.ReadAll on a request body in a handler.
pub(crate) fn detect_perf_21(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_handler(&facts.source_index) {
        return;
    }
    if !facts.source_index.has("io.ReadAll(") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "io.ReadAll" {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let arg = call.arguments[0].as_ref();
        if arg.contains("c.Request.Body")
            || arg.contains("r.Body")
            || arg.contains("req.Body")
            || arg.contains("ctx.Request.Body")
        {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_21,
                file,
                line,
                col,
                "io.ReadAll fully buffers a request body on a request path",
                out,
            );
            return;
        }
    }
}

/// PERF-022: os.ReadFile / ioutil.ReadFile inside a handler.
pub(crate) fn detect_perf_22(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_handler(&facts.source_index) {
        return;
    }
    if !facts.source_index.has("os.ReadFile(") && !facts.source_index.has("ioutil.ReadFile(") {
        return;
    }
    // sync.Once / loadOnce / similar indicates the file is loaded once at
    // startup, not per request. Suppress so the safe pattern does not fire.
    if facts.source_index.has("sync.Once")
        || facts.source_index.has("loadOnce")
        || facts.source_index.has("readOnce")
        || facts.source_index.has("fileOnce")
    {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "os.ReadFile" | "ioutil.ReadFile") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_22,
            file,
            line,
            col,
            "os.ReadFile is invoked on a request path; load the file once at startup",
            out,
        );
        return;
    }
}

/// PERF-023: bytes.NewReader allocation per request.
pub(crate) fn detect_perf_23(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_handler(&facts.source_index) {
        return;
    }

    for assignment in &facts.assignments {
        let text = assignment.text.as_ref();
        if !text.contains("bytes.NewReader(") {
            continue;
        }
        if !is_assignment_in_loop(assignment) && !text.contains(":=") {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_23,
            file,
            line,
            col,
            "bytes.NewReader is allocated per request; reuse a pooled buffer instead",
            out,
        );
        return;
    }
}

use super::super::super::super::common::{is_in_loop, is_request_path};
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-56: `c.JSON` inside a loop in a Gin handler.
pub(crate) fn detect_perf_56(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() == "c.JSON" && is_in_loop(call) {
            emit_at(
                unit,
                &META_PERF_56,
                call.start_byte,
                "c.JSON is called inside a loop body; marshal once and stream or batch the response",
                out,
            );
            return;
        }
    }
}

/// PERF-57: heavy allocation work in a Gin middleware / handler.
pub(crate) fn detect_perf_58(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let buffered = [
        "io.ReadAll(c.Request.Body)",
        "ioutil.ReadAll(c.Request.Body)",
        "io.ReadAll(r.Body)",
        "ioutil.ReadAll(r.Body)",
        "c.Request.Body.Read(",
    ];
    if !buffered.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("defer c.Request.Body.Close()")
        || source.contains("defer body.Close()")
        || source.contains("io.Copy(io.Discard,")
    {
        return;
    }
    let pos = first_pos(source, &buffered);
    emit_at(
        unit,
        &META_PERF_58,
        pos,
        "c.Request.Body is read in a buffered way without deferring Close or draining via io.Copy; the connection may be retained",
        out,
    );
}

/// PERF-59: `c.ShouldBindJSON` in a per-request handler.
pub(crate) fn detect_perf_59(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() == "c.ShouldBindJSON" {
            emit_at(
                unit,
                &META_PERF_59,
                call.start_byte,
                "c.ShouldBindJSON is called per request; consider sharing a pre-validated DTO or per-route binder",
                out,
            );
            return;
        }
    }
}

/// PERF-60: direct `render.JSON` / `render.HTML` allocation in a Gin handler.
pub(crate) fn detect_perf_60(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let trig = [
        "render.JSON{",
        "render.HTML{",
        "render.IndentedJSON{",
        "render.Redirect{",
        "render.XML{",
        "render.YAML{",
        "render.String{",
    ];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    emit_at(
        unit,
        &META_PERF_60,
        first_pos(source, &trig),
        "render.Render is allocated directly in a Gin handler; use c.JSON / c.HTML which manage a renderer pool",
        out,
    );
}

pub(super) fn match_gorc_body_end(from_brace: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    for (i, c) in from_brace.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

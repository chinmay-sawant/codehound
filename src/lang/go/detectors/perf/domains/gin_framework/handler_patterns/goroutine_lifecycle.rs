use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use super::request_io::match_gorc_body_end;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-61: `gin.Static` / `c.File` without cache header configuration.
pub(crate) fn detect_perf_64(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("go func()") || source.contains("c.Copy()") {
        return;
    }
    let go_pos = source.find("go func()").unwrap_or(0);
    let rest = &source[go_pos..];
    let Some(brace_start) = rest.find('{') else {
        return;
    };
    let body_end = match match_gorc_body_end(&rest[brace_start..]) {
        Some(end) => end,
        None => return,
    };
    let body = &rest[brace_start..=brace_start + body_end];
    let c_methods = [
        "c.JSON(",
        "c.AbortWithStatus(",
        "c.String(",
        "c.HTML(",
        "c.Request.",
        "c.Writer.",
    ];
    if !c_methods.iter().any(|t| body.contains(t)) {
        return;
    }
    emit_at(
        unit,
        &META_PERF_64,
        go_pos,
        "go func(){} uses *gin.Context; call c.Copy() before passing the context to a goroutine",
        out,
    );
}

/// PERF-65: `c.ShouldBind` in a middleware registered via `RouterGroup.Use`.
pub(crate) fn detect_perf_69(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let trig = ["c.Writer.Write(", "c.Stream("];
    if !trig.iter().any(|t| source.contains(t))
        || source.contains("c.Writer.Flush()")
        || source.contains("c.Writer.FlushHeaders()")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_69,
        first_pos(source, &trig),
        "c.Writer.Write / c.Stream is used without c.Writer.Flush(); streaming clients see higher time-to-first-byte",
        out,
    );
}

/// PERF-70: `go func(){}` in a Gin handler without a WaitGroup / done channel / context cancellation.
pub(crate) fn detect_perf_70(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("go func()") {
        return;
    }
    let has_lifecycle = source.contains("sync.WaitGroup")
        || source.contains("wg.Add(")
        || source.contains("done := make(chan")
        || source.contains("ctx, cancel := context.WithCancel")
        || source.contains("ctx, cancel := context.WithTimeout")
        || source.contains("ctx, cancel := context.WithDeadline")
        || source.contains("c.Request.Context()")
        || source.contains("sync.Once")
        || source.contains("errgroup")
        || source.contains("sem := make(chan")
        || source.contains("semaphore")
        || source.contains("workerPool")
        || source.contains("workerCount");
    if has_lifecycle {
        return;
    }
    emit_at(
        unit,
        &META_PERF_70,
        source.find("go func()").unwrap_or(0),
        "go func(){} in a Gin handler has no WaitGroup / done channel / context cancellation tied to the request",
        out,
    );
}

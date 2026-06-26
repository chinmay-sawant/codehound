use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-58: `c.Request.Body` read in a buffered way without a matching close / drain.
pub(crate) fn detect_perf_61(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let trig = ["gin.Static(", "router.Static(", "r.Static(", "c.File("];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("Cache-Control")
        || source.contains("cacheControl")
        || source.contains("MaxAge")
        || source.contains("Max-Age")
        || source.contains("c.Header(\"ETag\"")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_61,
        first_pos(source, &trig),
        "static file served without Cache-Control / ETag headers; configure cache headers or front with a CDN",
        out,
    );
}

/// PERF-66: more than 5 middlewares passed to a single `.Use(...)` call.
pub(crate) fn detect_perf_66(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains(".Use(") {
        return;
    }
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(".Use(") {
        let start = search_from + rel;
        let after = start + ".Use(".len();
        let mut depth: i32 = 1;
        let mut close_off: Option<usize> = None;
        for (i, c) in source[after..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close_off = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close_off) = close_off else { break };
        if top_commas(&source[after..after + close_off]) + 1 > 5 {
            emit_at(
                unit,
                &META_PERF_66,
                start,
                "more than 5 middlewares are passed to a single .Use(...) call; consider splitting into nested groups",
                out,
            );
            return;
        }
        search_from = after + close_off + 1;
    }
}

/// PERF-67: `gin.New()` without `gin.Recovery()`.
pub(crate) fn detect_perf_67(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("gin.New()") {
        return;
    }
    if source.contains("gin.Recovery()")
        || source.contains("gin.RecoveryWithWriter(")
        || source.contains("gin.CustomRecovery(")
        || source.contains("gin.CustomRecoveryWithWriter(")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_67,
        source.find("gin.New()").unwrap_or(0),
        "router is created with gin.New() but no gin.Recovery() middleware is installed",
        out,
    );
}

/// PERF-68: `gin.Logger()` (synchronous logger) installed on the router.
pub(crate) fn detect_perf_68(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("gin.Logger") {
        return;
    }
    if source.contains("Output: io.Discard")
        || source.contains("// logger disabled")
        || source.contains("LoggerConfig{Output:")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_68,
        source.find("gin.Logger").unwrap_or(0),
        "gin.Logger() performs synchronous I/O on the request path; use an async logger or disable in production",
        out,
    );
}

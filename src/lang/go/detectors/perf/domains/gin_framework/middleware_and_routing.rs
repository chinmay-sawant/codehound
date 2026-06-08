//! PERF-51 to PERF-70 detectors (gin_framework).
//!
//! Gin-specific performance heuristics covering middleware allocation, binding
//! patterns, render calls, static file caching, goroutine lifecycle, and other
//! hot-path concerns documented in `ruleset/golang/golang.json`.

use super::super::super::common::is_request_path;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// First byte offset containing any of `needles`, or 0 if none match.
fn first_pos(source: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter_map(|n| source.find(n))
        .min()
        .unwrap_or(0)
}

/// Count top-level (depth-0) commas in `s`. Used to size `.Use(...)` arg lists.
fn top_commas(s: &str) -> usize {
    let (mut depth, mut count) = (0i32, 0usize);
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Emit a single PERF finding anchored at `pos` in `unit.source`.
fn emit_at(
    unit: &ParsedUnit,
    meta: &'static crate::rules::RuleMetadata,
    pos: usize,
    msg: &str,
    out: &mut Vec<Finding>,
) {
    let (line, col) = unit.line_col(pos);
    emit::push_finding(meta, unit.display_path.as_str(), line, col, msg, out);
}

/// PERF-51: `unsafe.Pointer` in a request handler without benchmark justification.
pub(crate) fn detect_perf_51(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("unsafe.Pointer") {
        return;
    }
    if source.contains("// benchmark justifies unsafe.Pointer")
        || source.contains("// nolint:unsafe-ptr")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_51,
        source.find("unsafe.Pointer").unwrap_or(0),
        "unsafe.Pointer is used in a request handler; prefer safe alternatives unless a benchmark justifies the pattern",
        out,
    );
}

/// PERF-52: `runtime.GC()` outside tests, debug builds, or shutdown paths.
pub(crate) fn detect_perf_57(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source)
        || (!source.contains("*gin.Context") && !source.contains("gin.HandlerFunc"))
    {
        return;
    }
    // Only fire on actual middleware (functions that call c.Next()),
    // not on leaf handlers. Leaf handlers may legitimately need to
    // io.ReadAll or json.Unmarshal the request body.
    if !source.contains("c.Next()") {
        return;
    }
    // Detect io.ReadAll / json.Unmarshal in a Gin handler. Large `make([]byte, ...)`
    // allocations are intentionally not flagged here because they are routinely used
    // for sized buffers (e.g. `scanner.Buffer`) where the cost is bounded and the
    // allocation is reused.
    let trig = ["io.ReadAll(", "json.Unmarshal("];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    emit_at(
        unit,
        &META_PERF_57,
        first_pos(source, &trig),
        "heavy work in a Gin middleware (io.ReadAll / json.Unmarshal) runs for every request",
        out,
    );
}

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

/// PERF-62: complex `c.Param` parsing in middleware.
pub(crate) fn detect_perf_62(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("c.Param(") {
        return;
    }
    let has_parser = source.contains("regexp.MustCompile(")
        || source.contains("regexp.Compile(")
        || source.contains("json.Unmarshal(");
    if !has_parser {
        return;
    }
    emit_at(
        unit,
        &META_PERF_62,
        source.find("c.Param(").unwrap_or(0),
        "complex c.Param parsing (regex / json.Unmarshal) lives in middleware; move to the route handler that needs it",
        out,
    );
}

/// PERF-63: `binding.Validator.Engine()` invoked in a request handler.
pub(crate) fn detect_perf_63(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("binding.Validator.Engine()") {
        return;
    }
    if source.contains("var engine = binding.Validator.Engine()")
        || source.contains("once.Do(func()")
        || source.contains("sync.Once")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_63,
        source.find("binding.Validator.Engine()").unwrap_or(0),
        "binding.Validator.Engine() is invoked per request; cache the engine at startup",
        out,
    );
}

/// PERF-64: `go func()` using `*gin.Context` without `c.Copy()`.
pub(crate) fn detect_perf_65(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let middleware_registered = source.contains("r.Use(")
        || source.contains("RouterGroup.Use(")
        || source.contains("routerGroup.Use(")
        || source.contains("engine.Use(");
    if !middleware_registered || !source.contains("c.ShouldBind(") {
        return;
    }
    emit_at(
        unit,
        &META_PERF_65,
        source.find("c.ShouldBind(").unwrap_or(0),
        "c.ShouldBind runs in middleware registered via .Use(); it parses the body for every route in the chain",
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
        // Find the matching close paren of `.Use(`, not just the first `)`.
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

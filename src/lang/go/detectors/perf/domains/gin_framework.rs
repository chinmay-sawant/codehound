//! PERF-51 to PERF-70 detectors (gin_framework).
//!
//! Gin-specific performance heuristics covering middleware allocation, binding
//! patterns, render calls, static file caching, goroutine lifecycle, and other
//! hot-path concerns documented in `ruleset/golang/golang.json`.

use super::super::common::{is_in_loop, is_request_path};
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// First byte offset containing any of `needles`, or 0 if none match.
fn first_pos(source: &str, needles: &[&str]) -> usize {
    needles.iter().filter_map(|n| source.find(n)).min().unwrap_or(0)
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
fn emit_at(unit: &ParsedUnit, meta: &'static crate::rules::RuleMetadata, pos: usize, msg: &str, out: &mut Vec<Finding>) {
    let (line, col) = unit.line_col(pos);
    emit::push_finding(meta, unit.display_path.as_str(), line, col, msg, out);
}

/// PERF-51: `unsafe.Pointer` in a request handler without benchmark justification.
pub(crate) fn detect_perf_51(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("unsafe.Pointer") {
        return;
    }
    if source.contains("// benchmark justifies unsafe.Pointer") || source.contains("// nolint:unsafe-ptr") {
        return;
    }
    emit_at(unit, &META_PERF_51, source.find("unsafe.Pointer").unwrap_or(0),
        "unsafe.Pointer is used in a request handler; prefer safe alternatives unless a benchmark justifies the pattern", out);
}

/// PERF-52: `runtime.GC()` outside tests, debug builds, or shutdown paths.
pub(crate) fn detect_perf_52(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.GC" {
            continue;
        }
        emit_at(unit, &META_PERF_52, call.start_byte,
            "runtime.GC() forces a stop-the-world GC; remove unless required for tests or controlled shutdown", out);
        return;
    }
}

/// PERF-53: package-level `math/rand` on the request path.
pub(crate) fn detect_perf_53(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    let trig = ["rand.Intn(", "rand.Float64(", "rand.Read("];
    if !trig.iter().any(|t| source.contains(t)) || source.contains("rand.NewSource(") || source.contains("rand.New(") {
        return;
    }
    emit_at(unit, &META_PERF_53, first_pos(source, &trig),
        "package-level math/rand on a request path contends on a global mutex; use a per-goroutine rand.Source", out);
}

/// PERF-54: `strings.Builder{}` allocated in a request handler.
pub(crate) fn detect_perf_54(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("strings.Builder{}") {
        return;
    }
    if source.contains("Reset()") || source.contains("var builderPool =") || source.contains("sync.Pool{") {
        return;
    }
    emit_at(unit, &META_PERF_54, source.find("strings.Builder{}").unwrap_or(0),
        "strings.Builder is allocated per request; pool or hoist the builder and call Reset", out);
}

/// PERF-55: `bufio.NewScanner` with no explicit `Buffer` sizing.
pub(crate) fn detect_perf_55(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if source.contains("bufio.NewScanner(") && !source.contains(".Buffer(") {
        emit_at(unit, &META_PERF_55, source.find("bufio.NewScanner(").unwrap_or(0),
            "bufio.NewScanner is used without an explicit Buffer sizing; large inputs will silently fail at 64KiB", out);
    }
}

/// PERF-56: `c.JSON` inside a loop in a Gin handler.
pub(crate) fn detect_perf_56(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() == "c.JSON" && is_in_loop(call) {
            emit_at(unit, &META_PERF_56, call.start_byte,
                "c.JSON is called inside a loop body; marshal once and stream or batch the response", out);
            return;
        }
    }
}

/// PERF-57: heavy allocation work in a Gin middleware / handler.
pub(crate) fn detect_perf_57(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || (!source.contains("*gin.Context") && !source.contains("gin.HandlerFunc")) {
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
    emit_at(unit, &META_PERF_57, first_pos(source, &trig),
        "heavy work in a Gin middleware (io.ReadAll / json.Unmarshal) runs for every request", out);
}

/// PERF-58: `c.Request.Body` read in a buffered way without a matching close / drain.
pub(crate) fn detect_perf_58(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) {
        return;
    }
    // We flag the buffered-read anti-pattern (io.ReadAll / ioutil.ReadAll / direct
    // body Read) which definitely drains the connection. Streaming readers such as
    // `json.NewDecoder(c.Request.Body).Decode` are intentionally not flagged here
    // because the decoder does not buffer the entire body and the connection
    // management is handled differently.
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
    if source.contains("defer c.Request.Body.Close()") || source.contains("defer body.Close()")
        || source.contains("io.Copy(io.Discard,") {
        return;
    }
    let pos = first_pos(source, &buffered);
    emit_at(unit, &META_PERF_58, pos,
        "c.Request.Body is read in a buffered way without deferring Close or draining via io.Copy; the connection may be retained", out);
}

/// PERF-59: `c.ShouldBindJSON` in a per-request handler.
pub(crate) fn detect_perf_59(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    for call in &facts.calls {
        if call.callee.as_ref() == "c.ShouldBindJSON" {
            emit_at(unit, &META_PERF_59, call.start_byte,
                "c.ShouldBindJSON is called per request; consider sharing a pre-validated DTO or per-route binder", out);
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
    // `render.JSON{...}` / `render.HTML{...}` / `render.IndentedJSON{...}` are the
    // composite-literal form of allocating a renderer per request. Function-call
    // forms like `render.JSON.Render(w)` are not allocated.
    let trig = ["render.JSON{", "render.HTML{", "render.IndentedJSON{", "render.Redirect{",
        "render.XML{", "render.YAML{", "render.String{"];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    emit_at(unit, &META_PERF_60, first_pos(source, &trig),
        "render.Render is allocated directly in a Gin handler; use c.JSON / c.HTML which manage a renderer pool", out);
}

/// PERF-61: `gin.Static` / `c.File` without cache header configuration.
pub(crate) fn detect_perf_61(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let trig = ["gin.Static(", "router.Static(", "r.Static(", "c.File("];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("Cache-Control") || source.contains("cacheControl") || source.contains("MaxAge")
        || source.contains("Max-Age") || source.contains("c.Header(\"ETag\"") {
        return;
    }
    emit_at(unit, &META_PERF_61, first_pos(source, &trig),
        "static file served without Cache-Control / ETag headers; configure cache headers or front with a CDN", out);
}

/// PERF-62: complex `c.Param` parsing in middleware.
pub(crate) fn detect_perf_62(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("c.Param(") {
        return;
    }
    let has_parser = source.contains("regexp.MustCompile(") || source.contains("regexp.Compile(") || source.contains("json.Unmarshal(");
    if !has_parser {
        return;
    }
    emit_at(unit, &META_PERF_62, source.find("c.Param(").unwrap_or(0),
        "complex c.Param parsing (regex / json.Unmarshal) lives in middleware; move to the route handler that needs it", out);
}

/// PERF-63: `binding.Validator.Engine()` invoked in a request handler.
pub(crate) fn detect_perf_63(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("binding.Validator.Engine()") {
        return;
    }
    if source.contains("var engine = binding.Validator.Engine()") || source.contains("once.Do(func()") || source.contains("sync.Once") {
        return;
    }
    emit_at(unit, &META_PERF_63, source.find("binding.Validator.Engine()").unwrap_or(0),
        "binding.Validator.Engine() is invoked per request; cache the engine at startup", out);
}

/// PERF-64: `go func()` using `*gin.Context` without `c.Copy()`.
pub(crate) fn detect_perf_64(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("go func()") || source.contains("c.Copy()") {
        return;
    }
    let go_pos = source.find("go func()").unwrap_or(0);
    let rest = &source[go_pos..];
    // Find the body of the goroutine (`{ ... }` of the func literal) so we only
    // fire on a context method that is *inside* the goroutine, not one that
    // appears later in the handler.
    let Some(brace_start) = rest.find('{') else { return };
    let body_end = match match_gorc_body_end(&rest[brace_start..]) {
        Some(end) => end,
        None => return,
    };
    let body = &rest[brace_start..=brace_start + body_end];
    let c_methods = ["c.JSON(", "c.AbortWithStatus(", "c.String(", "c.HTML(", "c.Request.", "c.Writer."];
    if !c_methods.iter().any(|t| body.contains(t)) {
        return;
    }
    emit_at(unit, &META_PERF_64, go_pos,
        "go func(){} uses *gin.Context; call c.Copy() before passing the context to a goroutine", out);
}

/// Given a slice that starts at `{`, return the byte offset of the matching `}`
/// (relative to the start of the slice). Returns `None` if braces are unbalanced.
fn match_gorc_body_end(from_brace: &str) -> Option<usize> {
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

/// PERF-65: `c.ShouldBind` in a middleware registered via `RouterGroup.Use`.
pub(crate) fn detect_perf_65(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let middleware_registered = source.contains("r.Use(") || source.contains("RouterGroup.Use(")
        || source.contains("routerGroup.Use(") || source.contains("engine.Use(");
    if !middleware_registered || !source.contains("c.ShouldBind(") {
        return;
    }
    emit_at(unit, &META_PERF_65, source.find("c.ShouldBind(").unwrap_or(0),
        "c.ShouldBind runs in middleware registered via .Use(); it parses the body for every route in the chain", out);
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
            emit_at(unit, &META_PERF_66, start,
                "more than 5 middlewares are passed to a single .Use(...) call; consider splitting into nested groups", out);
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
    if source.contains("gin.Recovery()") || source.contains("gin.RecoveryWithWriter(")
        || source.contains("gin.CustomRecovery(") || source.contains("gin.CustomRecoveryWithWriter(") {
        return;
    }
    emit_at(unit, &META_PERF_67, source.find("gin.New()").unwrap_or(0),
        "router is created with gin.New() but no gin.Recovery() middleware is installed", out);
}

/// PERF-68: `gin.Logger()` (synchronous logger) installed on the router.
pub(crate) fn detect_perf_68(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("gin.Logger") {
        return;
    }
    if source.contains("Output: io.Discard") || source.contains("// logger disabled") || source.contains("LoggerConfig{Output:") {
        return;
    }
    emit_at(unit, &META_PERF_68, source.find("gin.Logger").unwrap_or(0),
        "gin.Logger() performs synchronous I/O on the request path; use an async logger or disable in production", out);
}

/// PERF-69: `c.Writer.Write` / `c.Stream` without `c.Writer.Flush()`.
pub(crate) fn detect_perf_69(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let trig = ["c.Writer.Write(", "c.Stream("];
    if !trig.iter().any(|t| source.contains(t)) || source.contains("c.Writer.Flush()") || source.contains("c.Writer.FlushHeaders()") {
        return;
    }
    emit_at(unit, &META_PERF_69, first_pos(source, &trig),
        "c.Writer.Write / c.Stream is used without c.Writer.Flush(); streaming clients see higher time-to-first-byte", out);
}

/// PERF-70: `go func(){}` in a Gin handler without a WaitGroup / done channel / context cancellation.
pub(crate) fn detect_perf_70(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("go func()") {
        return;
    }
    let has_lifecycle = source.contains("sync.WaitGroup") || source.contains("wg.Add(") || source.contains("done := make(chan")
        || source.contains("ctx, cancel := context.WithCancel") || source.contains("ctx, cancel := context.WithTimeout")
        || source.contains("ctx, cancel := context.WithDeadline") || source.contains("c.Request.Context()")
        || source.contains("sync.Once")
        || source.contains("errgroup") || source.contains("sem := make(chan") || source.contains("semaphore")
        || source.contains("workerPool") || source.contains("workerCount");
    if has_lifecycle {
        return;
    }
    emit_at(unit, &META_PERF_70, source.find("go func()").unwrap_or(0),
        "go func(){} in a Gin handler has no WaitGroup / done channel / context cancellation tied to the request", out);
}

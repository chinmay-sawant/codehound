//! PERF-101, 103, 118, 190, 198, 145: HTTP client misuse detectors.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{emit, Finding};

/// PERF-101: `http.Server{}` without any configured server timeout.
pub(crate) fn detect_perf_101(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("http.Server{") {
        let start = search_from + rel;
        let window = &source[start..(start + 256).min(source.len())];
        if window.contains("ReadTimeout:")
            || window.contains("ReadHeaderTimeout:")
            || window.contains("WriteTimeout:")
            || window.contains("IdleTimeout:")
        {
            search_from = start + "http.Server{".len();
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_101,
            file,
            line,
            col,
            "http.Server is missing ReadTimeout, WriteTimeout, and IdleTimeout settings",
            out,
        );
        search_from = start + "http.Server{".len();
    }
}

/// PERF-103: `client.Do`, `client.Get`, `http.Get`, or `http.Post`
/// returns an `*http.Response` whose Body must be `Close()`d. The
/// detector flags a call when the surrounding context does NOT
/// contain `defer ... Body.Close()`. A precise control-flow check
/// would be ideal; we approximate with a sibling-statement scan
/// inside the enclosing function block.
pub(crate) fn detect_perf_103(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(
            callee,
            "client.Do" | "http.Get" | "http.Post" | "http.PostForm" | "client.Get" | "client.Post"
        ) {
            continue;
        }

        // Look for `defer ... Body.Close()` anywhere later in the
        // function body. We use a window of the whole source rather
        // than a precise control-flow walk to keep the detector in
        // Category A; the trade-off is a small false-negative rate
        // for code that uses `defer` inside a nested closure, which
        // the higher-tier detectors will pick up.
        let window = &source[call.start_byte.min(source.len())..];
        if window.contains(".Body.Close()") || window.contains(".Body.Close(") {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_103,
            file,
            line,
            col,
            "http response body is not deferred-closed; this leaks the connection",
            out,
        );
    }
}

/// PERF-118: `http.NewRequest("GET"|"HEAD"|"POST", url, nil)` should
/// be the dedicated `http.NewRequest` for that method, or even
/// `http.Get` / `http.Head` when the body is nil.
pub(crate) fn detect_perf_118(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "http.NewRequest" {
            continue;
        }
        let method = call.arguments.first().map(|s| s.as_ref()).unwrap_or("");
        if !matches!(method, "\"GET\"" | "\"HEAD\"" | "\"POST\"") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_118,
            file,
            line,
            col,
            "use http.Get / http.Head / http.Post for trivial methods; http.NewRequest allocates extra fields",
            out,
        );
    }
}

/// PERF-190: `http.Client{}` without `Timeout`.
pub(crate) fn detect_perf_190(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("http.Client{") {
        let start = search_from + rel;
        let line_start = source[..start].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
        let line_prefix = source[line_start..start].trim_start();
        if line_prefix.starts_with("var ") {
            search_from = start + "http.Client{".len();
            continue;
        }
        let window = &source[start..(start + 192).min(source.len())];
        if window.contains("Timeout:") {
            search_from = start + "http.Client{".len();
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_190,
            file,
            line,
            col,
            "http.Client is missing Timeout; requests can hang indefinitely",
            out,
        );
        search_from = start + "http.Client{".len();
    }
}

/// PERF-198: `strings.Contains` on Content-Type is imprecise and slower
/// than parsing or exact media-type comparison.
pub(crate) fn detect_perf_198(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Contains" {
            continue;
        }
        let first = call.arguments.first().map(|arg| arg.as_ref()).unwrap_or("");
        if !first.contains("Content-Type") && !first.contains("contentType") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_198,
            file,
            line,
            col,
            "Content-Type checks should parse or compare the media type instead of using strings.Contains",
            out,
        );
    }
}

/// PERF-145: `r.WithContext(ctx)` in a function that looks like
/// HTTP middleware (named `Middleware`, takes a `http.Handler`,
/// or is registered via `engine.Use(...)` / `Group.Use(...)`).
/// The allocation is harmless per call but compounds on every
/// request.
pub(crate) fn detect_perf_145(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".WithContext(") {
        return;
    }
    if !is_middleware_shape(source) {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(".WithContext(") {
        let start = search_from + rel;
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_145,
            file,
            line,
            col,
            "r.WithContext allocates a new *http.Request per call; use a single context propagation in the handler chain",
            out,
        );
        search_from = start + ".WithContext(".len();
    }
}

fn is_middleware_shape(source: &str) -> bool {
    // A file is treated as "middleware-shaped" if it shows any of
    // the common middleware patterns. We deliberately accept
    // files that *contain* these patterns even if the immediate
    // caller is not the middleware itself; the call site is the
    // one allocation we want to flag.
    if source.contains("func Middleware")
        || source.contains("func (")
            && (source.contains("http.Handler")
                || source.contains("http.HandlerFunc")
                || source.contains("http.ResponseWriter"))
        || source.contains(".Use(")
        || source.contains("Group.Use")
        || source.contains("engine.Use")
    {
        return true;
    }
    false
}

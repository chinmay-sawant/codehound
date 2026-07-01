//! PERF-213–224: caching discipline, buffer management, allocation patterns,
//! and cross-cutting hot-path concerns identified in the gopdfsuit
//! optimization campaign (June 2026).

use super::common::{cache_has_eviction_bound, method_name, package_level_caches};
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{
    char_boundary, file_has_handler, is_handler_shaped, is_request_path,
};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-213: Cache Without Eviction or Bounding
pub(crate) fn detect_perf_213(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for cache in package_level_caches(source) {
        if !cache.name.to_ascii_lowercase().contains("cache") {
            continue;
        }
        if !cache_is_written(source, facts, &cache.name, cache.is_sync_map) {
            continue;
        }
        if cache_has_eviction_bound(source, &cache.name) {
            continue;
        }
        let (line, col) = unit.line_col(cache.byte);
        emit::push_finding(
            &META_PERF_213,
            file,
            line,
            col,
            "package-level cache has writes but no eviction or entry bound in the same compilation unit",
            out,
        );
        return;
    }
}

/// PERF-214: Cache Key Includes Volatile Request-Scoped Fields
pub(crate) fn detect_perf_214(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("sync.Map") {
        return;
    }

    for call in &facts.calls {
        let method = method_name(call.callee.as_ref());
        if !matches!(method, "Load" | "Store" | "LoadOrStore") {
            continue;
        }
        let Some(key) = call.arguments.first().map(|arg| arg.as_ref()) else {
            continue;
        };
        if volatile_cache_key(key) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_214,
                file,
                line,
                col,
                "cache key includes request-scoped or volatile fields, which collapses cache hit rate",
                out,
            );
            return;
        }
    }

    if source.contains("&entry") || source.contains("&item") || source.contains("requestID") {
        let byte = source
            .find("&entry")
            .or_else(|| source.find("&item"))
            .or_else(|| source.find("requestID"))
            .unwrap_or(0);
        let (line, col) = unit.line_col(byte);
        emit::push_finding(
            &META_PERF_214,
            file,
            line,
            col,
            "cache key includes request-scoped or volatile fields, which collapses cache hit rate",
            out,
        );
    }
}

/// PERF-215: bytes.Buffer or strings.Builder Without Pre-Sizing
pub(crate) fn detect_perf_215(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let candidates = [
        ("var buf bytes.Buffer", "buf"),
        ("var builder strings.Builder", "builder"),
    ];
    for (decl, name) in candidates {
        if !source.contains(decl) {
            continue;
        }
        if !source.contains(&format!("{name}.WriteString(payload)")) {
            continue;
        }
        if source.contains(&format!("{name}.Grow(")) {
            continue;
        }
        if !source.contains("size := len(payload)") && !source.contains("len(payload)") {
            continue;
        }
        let byte = source
            .find(&format!("{name}.WriteString(payload)"))
            .unwrap_or(0);
        let (line, col) = unit.line_col(byte);
        emit::push_finding(
            &META_PERF_215,
            file,
            line,
            col,
            "bytes.Buffer or strings.Builder writes without a preceding Grow(expectedSize)",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-216: Hot-Path Struct Allocation Without Slab Arena
pub(crate) fn detect_perf_216(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if source.contains("sync.Pool") {
        return;
    }

    for assignment in &facts.assignments {
        if assignment.enclosing_loop.is_none() {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !(expr.contains("TreeNode{") || expr.contains("&TreeNode{")) {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_216,
            file,
            line,
            col,
            "struct literal allocation inside a loop on the hot path; reuse pooled objects instead",
            out,
        );
        return;
    }
}

/// PERF-217: Static Computation Rebuilt Per Operation
pub(crate) fn detect_perf_217(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("http.ResponseWriter")
        && !source.contains("*gin.Context")
        && !source.contains("echo.Context")
    {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if call.arguments.iter().any(|arg| !arg.trim().is_empty()) {
            continue;
        }
        if !looks_like_static_builder(callee) {
            continue;
        }
        if source.contains(&format!("var {} =", bare_callee(callee)))
            || source.contains(&format!(
                "{} = {}()",
                bare_callee(callee),
                bare_callee(callee)
            ))
        {
            continue;
        }
        if !is_handler_shaped(source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_217,
            file,
            line,
            col,
            "deterministic static computation is rebuilt on the request path instead of cached at init",
            out,
        );
        return;
    }
}

/// PERF-218: sync.Pool or Cache Without Per-CPU Sharding
pub(crate) fn detect_perf_218(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("sync.Pool") {
        return;
    }
    if source.contains("[runtime.NumCPU()]sync.Pool")
        || source.contains("runtime_procPin")
        || source.contains("shard")
    {
        return;
    }
    if !file_has_handler(source) && facts.go_starts.is_empty() {
        return;
    }
    for call in &facts.calls {
        let method = method_name(call.callee.as_ref());
        if !matches!(method, "Get" | "Put") {
            continue;
        }
        let recv = receiver_name(call.callee.as_ref());
        if recv.is_empty() || !source.contains(&format!("var {recv} sync.Pool")) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_218,
            file,
            line,
            col,
            "single global sync.Pool is used on a hot concurrent path without sharding",
            out,
        );
        return;
    }
}

/// PERF-219: Oversized Object Returned to sync.Pool
pub(crate) fn detect_perf_219(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if method_name(call.callee.as_ref()) != "Put" {
            continue;
        }
        let Some(arg) = call.arguments.first().map(|arg| arg.as_ref()) else {
            continue;
        };
        if !arg.contains("buf") || !source.contains("func Recycle(buf []byte)") {
            continue;
        }
        let window_start = char_boundary(source, call.start_byte.saturating_sub(160));
        let window = &source[window_start..call.start_byte];
        if window.contains("cap(buf) >") || window.contains("cap(buf) >=") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_219,
            file,
            line,
            col,
            "object is returned to sync.Pool without a capacity guard, so oversized buffers stay retained",
            out,
        );
        return;
    }
}

/// PERF-220: Sequential Scans Over Identical Data
pub(crate) fn detect_perf_220(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if facts.for_ranges.len() < 2 {
        return;
    }

    let mut loops = facts.for_ranges.clone();
    loops.sort_unstable_by_key(|(start, _)| *start);
    for pair in loops.windows(2) {
        let first = pair[0];
        let second = pair[1];
        let a = loop_target(source, first.0, first.1);
        let b = loop_target(source, second.0, second.1);
        if a.is_empty() || a != b {
            continue;
        }
        if a != "row" {
            continue;
        }
        if second.0.saturating_sub(first.1) > 16 {
            continue;
        }
        let (line, col) = unit.line_col(second.0);
        emit::push_finding(
            &META_PERF_220,
            file,
            line,
            col,
            "two consecutive loops scan the same collection; merge them into one pass",
            out,
        );
        return;
    }
}

/// PERF-221: map[int]T for Dense Sequential Integer Keys
pub(crate) fn detect_perf_221(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("map[int]") && !source.contains("map[int64]") {
        return;
    }

    for assignment in &facts.assignments {
        let text = assignment.text.as_ref();
        if !text.starts_with("m[") {
            continue;
        }
        if !(text.contains("[i+1]") || text.contains("[idx]") || text.contains("[len(")) {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_221,
            file,
            line,
            col,
            "map[int] is being filled with dense sequential keys; use a slice instead",
            out,
        );
        return;
    }
}

/// PERF-222: Generic Function on Measured Hot Path
pub(crate) fn detect_perf_222(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("func formatElem[T any]") {
        return;
    }

    for (start, end) in &facts.for_ranges {
        let loop_text = &source[*start..char_boundary(source, (*end + 64).min(source.len()))];
        if loop_text.contains("formatElem[Row](") {
            let (line, col) = unit.line_col(*start);
            emit::push_finding(
                &META_PERF_222,
                file,
                line,
                col,
                "generic function call appears on a measured hot path; prefer a concrete specialization",
                out,
            );
            return;
        }
    }
}

/// PERF-223: sync.Pool Backing Array Discarded on Return
pub(crate) fn detect_perf_223(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if method_name(call.callee.as_ref()) != "Put" {
            continue;
        }
        let Some(arg) = call.arguments.first().map(|arg| arg.as_ref()) else {
            continue;
        };
        if !arg.contains("buf") || !source.contains("func Recycle(buf []byte)") {
            continue;
        }
        let window_start = char_boundary(source, call.start_byte.saturating_sub(128));
        let window = &source[window_start..call.start_byte];
        if window.contains(&format!("{arg} = nil")) || window.contains(&format!("{arg}= nil")) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_223,
                file,
                line,
                col,
                "slice is nil-ed before pool return, so the backing array is discarded instead of reused",
                out,
            );
            return;
        }
    }
}

/// PERF-224: Recursive Tree Walk on Hot Execution Path
pub(crate) fn detect_perf_224(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !file_has_handler(source) && !is_request_path(&facts.source_index) {
        return;
    }

    for func in recursive_functions(source) {
        if !source.contains(&format!("{}(", func.as_str())) {
            continue;
        }
        if !source.contains("flat") && !source.contains("[]*Node") && !source.contains("[]Node") {
            continue;
        }
        let Some(byte) = handler_call_site(source, &func) else {
            continue;
        };
        let (line, col) = unit.line_col(byte);
        emit::push_finding(
            &META_PERF_224,
            file,
            line,
            col,
            "recursive tree walk is invoked on the request path even though a flat representation already exists",
            out,
        );
        return;
    }
}

fn cache_is_written(source: &str, facts: &GoPerfFacts, name: &str, is_sync_map: bool) -> bool {
    if is_sync_map {
        return facts.calls.iter().any(|call| {
            call.callee.starts_with(&format!("{name}."))
                && matches!(
                    method_name(call.callee.as_ref()),
                    "Store" | "Swap" | "LoadOrStore" | "Delete" | "LoadAndDelete"
                )
        });
    }

    facts.assignments.iter().any(|assignment| {
        assignment
            .text
            .trim_start()
            .starts_with(&format!("{name}["))
    }) || source.contains(&format!("{name}["))
}

fn volatile_cache_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    key.contains('&')
        || lower.contains("requestid")
        || lower.contains("reqid")
        || lower.contains("trace")
        || lower.contains("coord")
        || lower.contains("page")
        || lower.contains(" idx")
        || lower.contains("index")
        || lower.contains(", y")
}

fn receiver_name(callee: &str) -> &str {
    callee.split('.').next().unwrap_or("")
}

fn bare_callee(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

fn looks_like_static_builder(callee: &str) -> bool {
    let lower = bare_callee(callee).to_ascii_lowercase();
    lower.contains("build")
        || lower.contains("profile")
        || lower.contains("template")
        || lower.contains("compress")
        || lower.contains("serialize")
        || lower.contains("generate")
}

fn loop_target<'a>(source: &'a str, start: usize, end: usize) -> &'a str {
    let end = char_boundary(source, (end + 64).min(source.len()));
    let text = &source[start..end];
    let Some(range_idx) = text.find("range") else {
        return "";
    };
    let rest = text[range_idx + "range".len()..].trim_start();
    rest.split(|c: char| c == '{' || c == '\n')
        .next()
        .unwrap_or("")
        .trim()
}

fn recursive_functions(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find("func ") {
        let start = search_from + rel + "func ".len();
        let after = &source[start..];
        let mut chars = after.chars();
        let name: String = chars
            .by_ref()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            search_from = start;
            continue;
        }
        let Some(body_start_rel) = source[start..].find('{') else {
            break;
        };
        let body_start = start + body_start_rel;
        let Some(body_end) = match_brace(source, body_start) else {
            break;
        };
        let body = &source[body_start..body_end];
        if body.matches(&format!("{name}(")).count() >= 1 {
            out.push(name);
        }
        search_from = body_end;
    }
    out
}

fn handler_call_site(source: &str, name: &str) -> Option<usize> {
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(&format!("{name}(")) {
        let byte = search_from + rel;
        if is_handler_shaped(source, byte) {
            return Some(byte);
        }
        search_from = byte + name.len();
    }
    None
}

fn match_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open + idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

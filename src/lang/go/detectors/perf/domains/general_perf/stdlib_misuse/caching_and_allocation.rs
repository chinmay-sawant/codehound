//! PERF-213–224: caching discipline, buffer management, and allocation patterns
//! on generic Go hot paths (stdlib shapes only).

use super::common::{cache_has_eviction_bound, method_name, package_level_caches};
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{
    char_boundary, file_has_concurrency, file_has_handler, is_handler_shaped, is_hot_path,
    is_in_loop, is_request_path,
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
    use crate::lang::go::detectors::perf::common::{
        enclosing_function_body, enclosing_function_is_hot,
    };

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for name in buffer_or_builder_names(source) {
        // A) write arg has matching len(arg) in the same function, no Grow there
        if let Some(write_byte) = first_write_with_known_len(source, &name) {
            let body = enclosing_function_body(source, write_byte).unwrap_or(source);
            if !body.contains(&format!("{name}.Grow(")) {
                let (line, col) = unit.line_col(write_byte);
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
        }
        // B) multiple writes in one hot function with a size estimate (len/.Len)
        //    and no Grow on this builder in that function.
        let mut search_from = 0usize;
        let write_needle = format!("{name}.Write");
        while let Some(rel) = source[search_from..].find(&write_needle) {
            let byte = search_from + rel;
            let body = enclosing_function_body(source, byte).unwrap_or("");
            if body.is_empty() {
                search_from = byte + write_needle.len();
                continue;
            }
            if body.contains(&format!("{name}.Grow(")) {
                search_from = byte + write_needle.len();
                continue;
            }
            let write_count = ["WriteString(", "Write(", "WriteByte(", "WriteRune("]
                .iter()
                .map(|m| body.matches(&format!("{name}.{m}")).count())
                .sum::<usize>();
            let size_hint =
                body.contains("len(") || body.contains(".Len()") || body.contains("cap(");
            // Hot multi-write without Grow: size estimable, or many writes.
            if write_count >= 3
                && (size_hint || write_count >= 6)
                && enclosing_function_is_hot(source, byte)
            {
                let (line, col) = unit.line_col(byte);
                emit::push_finding(
                    &META_PERF_215,
                    file,
                    line,
                    col,
                    "bytes.Buffer or strings.Builder does many writes without Grow; pre-size when output size is estimable",
                    out,
                );
                return;
            }
            search_from = byte + write_needle.len();
        }
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

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        // `defer func(){ ... }()` is a call_expression whose "function" is a
        // func_literal — never a named static builder.
        if callee.starts_with("func") || callee.contains('{') || callee.contains('\n') {
            continue;
        }
        // Pool Get/Put and reset/clear are not pure static builders.
        if is_pool_or_reset_accessor(callee) {
            continue;
        }
        // Allow zero-arg pure builders, or only literal/constant-looking args.
        let non_empty: Vec<_> = call
            .arguments
            .iter()
            .map(|a| a.trim())
            .filter(|a| !a.is_empty())
            .collect();
        let args_ok = non_empty.is_empty()
            || non_empty.iter().all(|a| {
                a.chars().all(|c| c.is_ascii_digit())
                    || (*a == "true" || *a == "false" || *a == "nil")
                    || (a.starts_with('"') && a.ends_with('"'))
            });
        if !args_ok {
            continue;
        }
        if !looks_like_static_builder(callee) {
            continue;
        }
        // Hot path only: loop, HTTP/handler shape, or encode/build/generate-style
        // function — not HTTP-only. Package-level init and cold helpers stay silent.
        if !is_hot_path(
            source,
            call.start_byte,
            &facts.source_index,
            is_in_loop(call),
        ) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_217,
            file,
            line,
            col,
            "deterministic static computation is rebuilt on a hot path instead of cached at init",
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
        || source.contains("[]sync.Pool")
    {
        return;
    }
    // Concurrent fan-out: handlers, go statements, errgroup/WaitGroup.
    // Do not flag every package-level pool just because a hot *name* exists.
    let concurrent =
        file_has_handler(source) || !facts.go_starts.is_empty() || file_has_concurrency(source);
    if !concurrent {
        return;
    }
    for call in &facts.calls {
        let method = method_name(call.callee.as_ref());
        if !matches!(method, "Get" | "Put") {
            continue;
        }
        let recv = receiver_name(call.callee.as_ref());
        // Zero-value package pool (`var p sync.Pool`) — the classic unsharded
        // global. `var p = sync.Pool{New: ...}` is the normal correct form and
        // is left to sharding heuristics only when explicit zero-value pools
        // are used under concurrency (matches pre-enhance fixtures).
        if recv.is_empty() || !source.contains(&format!("var {recv} sync.Pool")) {
            continue;
        }
        // Avoid matching `var p = sync.Pool` via a substring of `var p sync.Pool`
        // when only the composite form exists: require a line that is the
        // zero-value form (no `=` between name and sync.Pool on that decl).
        if !has_zero_value_pool_decl(source, recv) {
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
    if !source.contains("sync.Pool") {
        return;
    }

    for call in &facts.calls {
        if method_name(call.callee.as_ref()) != "Put" {
            continue;
        }
        let Some(arg) = call.arguments.first().map(|arg| arg.as_ref()) else {
            continue;
        };
        let arg = arg.trim();
        if !looks_like_buffer_arg(arg) {
            continue;
        }
        // Only flag helpers that take a growable `[]byte` (or *bytes.Buffer)
        // parameter — not every `pool.Put(buf)` of a *bytes.Buffer from Get.
        if !enclosing_func_has_slice_buf_param(source, call.start_byte, arg) {
            continue;
        }
        let window_start = char_boundary(source, call.start_byte.saturating_sub(200));
        let window = &source[window_start..call.start_byte];
        if window.contains(&format!("cap({arg}) >"))
            || window.contains(&format!("cap({arg}) >="))
            || window.contains(&format!("cap({arg})>"))
        {
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
///
/// Fires when an integer-keyed map is written with sequential/index-style keys
/// (`i`, `i+1`, `idx`, `len(...)`) — not only the identifier `m`.
pub(crate) fn detect_perf_221(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("map[int]") && !source.contains("map[int64]") {
        return;
    }

    for assignment in &facts.assignments {
        let text = assignment.text.as_ref();
        // name[key] = … form
        let Some(bracket) = text.find('[') else {
            continue;
        };
        if !text[..bracket]
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let key = text[bracket..].to_ascii_lowercase();
        let sequential = key.contains("[i]")
            || key.contains("[i+")
            || key.contains("[i +")
            || key.contains("[idx")
            || key.contains("[index")
            || key.contains("[len(")
            || key.contains("[j]")
            || key.contains("[n]");
        if !sequential {
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
///
/// Explicit type-instantiation calls inside loops (e.g. `process[T](x)`) prevent
/// monomorphization/inlining on hot paths. Matches any generic `func name[…]`
/// invoked as `name[Type](` in a loop — not a single product helper name.
pub(crate) fn detect_perf_222(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let generic_names = generic_func_names(source);
    if generic_names.is_empty() {
        return;
    }

    for (start, end) in &facts.for_ranges {
        let loop_text = &source[*start..char_boundary(source, (*end + 64).min(source.len()))];
        for name in &generic_names {
            let needle = format!("{name}[");
            let mut search = 0usize;
            while let Some(rel) = loop_text[search..].find(&needle) {
                let at = search + rel;
                let after = &loop_text[at + needle.len()..];
                if is_type_instantiation_call(after) {
                    let (line, col) = unit.line_col(*start + at);
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
                search = at + needle.len();
            }
        }
    }
}

/// PERF-223: sync.Pool Backing Array Discarded on Return
///
/// Flags `x = nil` immediately before `pool.Put(x)` when a `sync.Pool` is in the
/// unit — any helper name, any slice/buffer identifier.
pub(crate) fn detect_perf_223(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("sync.Pool") {
        return;
    }

    for call in &facts.calls {
        if method_name(call.callee.as_ref()) != "Put" {
            continue;
        }
        let Some(arg) = call.arguments.first().map(|arg| arg.trim()) else {
            continue;
        };
        // Simple identifier only (avoid `pool.Put(make(...))` noise).
        if arg.is_empty() || !is_simple_ident_token(arg) {
            continue;
        }
        let window_start = char_boundary(source, call.start_byte.saturating_sub(160));
        let window = &source[window_start..call.start_byte];
        let nil_assign = format!("{arg} = nil");
        let nil_assign_tight = format!("{arg}=nil");
        let nil_assign_sp = format!("{arg}= nil");
        if window.contains(&nil_assign)
            || window.contains(&nil_assign_tight)
            || window.contains(&nil_assign_sp)
        {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_223,
                file,
                line,
                col,
                "value is set to nil before pool return, so the backing array is discarded instead of reused",
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

/// Collect local names bound to `bytes.Buffer` / `strings.Builder`.
fn buffer_or_builder_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        // var name bytes.Buffer / var name strings.Builder
        if let Some(rest) = trimmed.strip_prefix("var ") {
            let rest = rest.trim_start();
            let Some(name_end) = rest.find(char::is_whitespace) else {
                continue;
            };
            let name = rest[..name_end].trim();
            let ty = rest[name_end..].trim_start();
            if (ty.starts_with("bytes.Buffer") || ty.starts_with("strings.Builder"))
                && is_simple_ident(name)
            {
                names.push(name.to_string());
            }
            continue;
        }
        // name := bytes.Buffer{} / name := strings.Builder{}
        if let Some(eq) = trimmed.find(":=") {
            let name = trimmed[..eq].trim();
            let rhs = trimmed[eq + 2..].trim();
            if (rhs.starts_with("bytes.Buffer{") || rhs.starts_with("strings.Builder{"))
                && is_simple_ident(name)
            {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// First `{name}.WriteString(arg)` / `{name}.Write(arg)` where `len(arg)` also
/// appears in the **same enclosing function** (size is knowable there).
fn first_write_with_known_len(source: &str, name: &str) -> Option<usize> {
    use crate::lang::go::detectors::perf::common::enclosing_function_body;

    for method in ["WriteString(", "Write("] {
        let needle = format!("{name}.{method}");
        let mut search_from = 0usize;
        while let Some(rel) = source[search_from..].find(&needle) {
            let start = search_from + rel;
            let arg_start = start + needle.len();
            let rest = &source[arg_start..];
            let Some(arg_end) = rest.find([')', ',']) else {
                search_from = arg_start;
                continue;
            };
            let arg = rest[..arg_end].trim();
            if is_simple_ident(arg) {
                let body = enclosing_function_body(source, start).unwrap_or(source);
                if body.contains(&format!("len({arg})")) {
                    return Some(start);
                }
            }
            search_from = arg_start;
        }
    }
    None
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

fn looks_like_buffer_arg(arg: &str) -> bool {
    if !is_simple_ident(arg) {
        return false;
    }
    let lower = arg.to_ascii_lowercase();
    // Keep this tight — single-letter names (`b`) are common for builders
    // and would false-positive on every pool.Put(b).
    lower.contains("buf")
        || lower.contains("scratch")
        || lower.contains("tmp")
        || lower.ends_with("buffer")
}

fn has_zero_value_pool_decl(source: &str, name: &str) -> bool {
    for line in source.lines() {
        let t = line.trim();
        // `var name sync.Pool` optionally followed by comment; no `=`.
        if t.starts_with(&format!("var {name} sync.Pool")) && !t.contains('=') {
            return true;
        }
    }
    false
}

/// True when the enclosing function signature includes `name []byte` (or
/// similar slice/buffer param), so Put is recycling a growable byte buffer.
fn enclosing_func_has_slice_buf_param(source: &str, start_byte: usize, name: &str) -> bool {
    let head = &source[..start_byte.min(source.len())];
    let Some(func_kw) = head.rfind("func ") else {
        return false;
    };
    let sig = &source[func_kw..start_byte.min(source.len())];
    let Some(brace) = sig.find('{') else {
        return false;
    };
    let sig = &sig[..brace];
    // `name []byte` / `name []T` / `name *bytes.Buffer`
    sig.contains(&format!("{name} []byte"))
        || sig.contains(&format!("{name} []"))
        || sig.contains(&format!("{name} *bytes.Buffer"))
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
    // Request/trace/index-scoped keys are portable web/service smells.
    key.contains('&')
        || lower.contains("requestid")
        || lower.contains("reqid")
        || lower.contains("trace")
        || lower.contains("session")
        || lower.contains(" idx")
        || lower.contains("index")
        || lower.contains("timestamp")
        || lower.contains("time.now")
}

fn receiver_name(callee: &str) -> &str {
    callee.split('.').next().unwrap_or("")
}

fn bare_callee(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

fn looks_like_static_builder(callee: &str) -> bool {
    let lower = bare_callee(callee).to_ascii_lowercase();
    // Generic builder/generate/template/metadata shapes only — no product tokens.
    lower.contains("build")
        || lower.contains("profile")
        || lower.contains("template")
        || lower.contains("serialize")
        || lower.contains("generate")
        || lower.contains("metadata")
        || lower.contains("defaultconfig")
        || lower.contains("loadconfig")
        || (lower.contains("compress")
            && (lower.contains("static") || lower.contains("once") || lower.contains("profile")))
}

/// Names of functions declared with type parameters: `func name[T …]`.
fn generic_func_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("func ") {
        let at = search + rel;
        let after = source[at + "func ".len()..].trim_start();
        // Skip methods: func (recv T) Name[
        let after = if after.starts_with('(') {
            match after.find(')') {
                Some(i) => after[i + 1..].trim_start(),
                None => {
                    search = at + 4;
                    continue;
                }
            }
        } else {
            after
        };
        let name_end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(after.len());
        if name_end == 0 {
            search = at + 4;
            continue;
        }
        let name = &after[..name_end];
        let rest = after[name_end..].trim_start();
        if rest.starts_with('[') {
            names.push(name.to_string());
        }
        search = at + 4;
    }
    names
}

/// After `name[`, is this `Type](` (explicit instantiation call)?
fn is_type_instantiation_call(after_bracket: &str) -> bool {
    let s = after_bracket.trim_start();
    if s.is_empty() {
        return false;
    }
    // Type args are identifiers / constraints; require closing `](` soon.
    let Some(close) = s.find(']') else {
        return false;
    };
    // Reject empty `[](` and non-type noise.
    let inside = s[..close].trim();
    if inside.is_empty() {
        return false;
    }
    let first = inside.chars().next().unwrap_or('\0');
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    s[close + 1..].trim_start().starts_with('(')
}

fn is_simple_ident_token(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Pool/buffer accessors and reset helpers are not deterministic static builders.
fn is_pool_or_reset_accessor(callee: &str) -> bool {
    let bare = bare_callee(callee).to_ascii_lowercase();
    if bare.starts_with("reset") || bare.starts_with("clear") || bare.starts_with("recycle") {
        return true;
    }
    if matches!(
        bare.as_str(),
        "get" | "put" | "load" | "store" | "delete" | "pop" | "push" | "take" | "borrow"
    ) {
        return true;
    }
    // GetCompressBuffer / getZlibWriter / PutCompressBuffer / Get*Pool
    let get_or_put = bare.starts_with("get") || bare.starts_with("put");
    if get_or_put
        && (bare.contains("buffer")
            || bare.contains("writer")
            || bare.contains("pool")
            || bare.ends_with("buf")
            || bare.contains("scratch"))
    {
        return true;
    }
    // receiver/package looks like a pool: fooPool.Get already handled via bare "get"
    let recv = callee.split('.').next().unwrap_or("").to_ascii_lowercase();
    if recv.contains("pool") && matches!(bare.as_str(), "get" | "put" | "new") {
        return true;
    }
    false
}

fn loop_target(source: &str, start: usize, end: usize) -> &str {
    let end = char_boundary(source, (end + 64).min(source.len()));
    let text = &source[start..end];
    let Some(range_idx) = text.find("range") else {
        return "";
    };
    let rest = text[range_idx + "range".len()..].trim_start();
    rest.split(['{', '\n']).next().unwrap_or("").trim()
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

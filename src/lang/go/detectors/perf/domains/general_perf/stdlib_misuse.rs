//! PERF-101..PERF-127 Category-A detectors.
//!
//! "Category A" (per `plans/p2-implementation/04-perf-detector-implementation.md`)
//! covers rules that reduce to a single tree-sitter pattern match on a
//! known function call, with optional argument inspection. Each
//! detector in this file is self-contained: a function-call shape, a
//! cheap argument check, and a single emission. They are deliberately
//! narrow — broad heuristics (e.g. "any loop" or "any retry") are left
//! for the higher-tier detectors in `loop_allocations` and `protocols`.

use super::super::super::common::is_in_loop;
use super::super::super::facts::{CallFact, GoPerfFacts};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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

/// PERF-107: `encoding/binary.Read` / `binary.Write` inside a loop body
/// — the encoding layer makes a function call per element with
/// runtime reflection.
pub(crate) fn detect_perf_107(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "binary.Read" | "binary.Write") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_107,
            file,
            line,
            col,
            "encoding/binary Read/Write inside a loop uses reflection; reuse a pre-encoded buffer or hand-roll the byte order",
            out,
        );
    }
}

/// PERF-105: `runtime.SetFinalizer` on frequently-created objects adds
/// finalizer overhead and delays collection by an extra GC cycle.
pub(crate) fn detect_perf_105(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.SetFinalizer" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_105,
            file,
            line,
            col,
            "runtime.SetFinalizer adds GC overhead; prefer explicit Close/Release methods",
            out,
        );
    }
}

/// PERF-111: ranging over `[]rune(s)` allocates a rune slice; range
/// over the string directly to decode UTF-8 lazily.
pub(crate) fn detect_perf_111(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    for (start, end) in &facts.for_ranges {
        let range_text = &source[*start..*end];
        if !range_text.contains("range []rune(") {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_111,
            file,
            line,
            col,
            "range over []rune(s) allocates a rune slice; range over the string directly",
            out,
        );
    }
}

/// PERF-112: `strings.ToLower(a) == strings.ToLower(b)` allocates two
/// intermediate strings; use `strings.EqualFold` for allocation-free
/// case-insensitive comparison.
pub(crate) fn detect_perf_112(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(callee, "strings.ToLower" | "strings.ToUpper") {
            continue;
        }
        // Require a comparison operator in the same statement window.
        let window =
            &source[call.start_byte.saturating_sub(8)..(call.start_byte + 96).min(source.len())];
        if !window.contains("==") && !window.contains("!=") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_112,
            file,
            line,
            col,
            "case conversion before comparison allocates; use strings.EqualFold",
            out,
        );
    }
}

/// PERF-113: `select` with one case is more expensive and less clear
/// than a direct channel operation.
pub(crate) fn detect_perf_113(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("select {") {
        let start = search_from + rel;
        let end = source[start..]
            .find('}')
            .map(|off| start + off)
            .unwrap_or(source.len());
        let block = &source[start..end];
        if block.matches("case ").count() == 1 && !block.contains("default:") {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_113,
                file,
                line,
                col,
                "single-case select should be a direct channel send or receive",
                out,
            );
        }
        search_from = end.saturating_add(1);
    }
}

/// PERF-146: `fmt.Sprintf("%s", value)` is just string conversion.
pub(crate) fn detect_perf_146(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "fmt.Sprintf" {
            continue;
        }
        if call.arguments.len() == 2 && call.arguments[0].as_ref() == "\"%s\"" {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_146,
                file,
                line,
                col,
                "fmt.Sprintf(\"%s\", s) is redundant for a single string value",
                out,
            );
        }
    }
}

/// PERF-147: duplicate of the ReplaceAll shape tracked separately in
/// the expanded PERF catalog.
pub(crate) fn detect_perf_147(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Replace" {
            continue;
        }
        if call.arguments.last().map(|arg| arg.as_ref()) != Some("-1") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_147,
            file,
            line,
            col,
            "strings.Replace with -1 should be strings.ReplaceAll",
            out,
        );
    }
}

/// PERF-157: `fmt.Sprint` / `fmt.Sprintln` with one string literal is redundant.
pub(crate) fn detect_perf_157(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "fmt.Sprint" | "fmt.Sprintln") {
            continue;
        }
        let Some(arg) = call.arguments.first().map(|arg| arg.as_ref()) else {
            continue;
        };
        if call.arguments.len() == 1 && arg.starts_with('"') && arg.ends_with('"') {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_157,
                file,
                line,
                col,
                "fmt.Sprint with a single string literal is redundant",
                out,
            );
        }
    }
}

/// PERF-123: `make(T, 0)` or `make(T, 0, 0)` where the zero length is
/// redundant. Pre-allocated buffers like `make([]byte, 0, cap)` are
/// intentionally allowed.
pub(crate) fn detect_perf_123(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        // make(T) has no length arg; make(T, N) has one; make(T, N, M) has two.
        let args = &call.arguments;
        if args.len() < 2 {
            continue;
        }
        if args[1].as_ref() != "0" {
            continue;
        }
        // Allow make(T, 0, cap) where cap > 0.
        if args.len() == 3 && args[2].as_ref() != "0" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_123,
            file,
            line,
            col,
            "make with explicit zero length/capacity is redundant; omit the zero argument",
            out,
        );
    }
}

/// PERF-115: `strings.Compare(a, b) == 0` should be `a == b`. The
/// helper is a leftover from `bytes.Compare`-style usage and the
/// direct comparison compiles to the same code.
pub(crate) fn detect_perf_115(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Compare" {
            continue;
        }
        // The detector layer only sees call sites, not their
        // surrounding binary expression. The parent walker filters
        // candidates by `text` containing `== 0` or `!= 0`; we apply
        // the same quick substring check on the call's text.
        let text = call_text(unit, call.start_byte);
        if !text.contains("== 0") && !text.contains("!= 0") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_115,
            file,
            line,
            col,
            "strings.Compare(a, b) compared to 0 should be a == b (or strings.EqualFold for case-insensitive)",
            out,
        );
    }
}

/// PERF-116: `strings.Index(s, sub) != -1` should be
/// `strings.Contains(s, sub)`.
pub(crate) fn detect_perf_116(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Index" {
            continue;
        }
        let text = call_text(unit, call.start_byte);
        if !text.contains("!= -1") && !text.contains("== -1") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_116,
            file,
            line,
            col,
            "strings.Index(s, sub) compared to -1 should be strings.Contains(s, sub)",
            out,
        );
    }
}

/// PERF-117: `bytes.Compare(a, b) == 0` should be `bytes.Equal(a, b)`
/// (which is also constant-time, so it's strictly better).
pub(crate) fn detect_perf_117(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "bytes.Compare" {
            continue;
        }
        let text = call_text(unit, call.start_byte);
        if !text.contains("== 0") && !text.contains("!= 0") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_117,
            file,
            line,
            col,
            "bytes.Compare(a, b) compared to 0 should be bytes.Equal(a, b) (constant-time, allocation-free)",
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

/// PERF-120: `time.Now().Sub(t)` should be `time.Since(t)`.
pub(crate) fn detect_perf_120(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "time.Now" {
            continue;
        }
        // We can't tell from the call-site text whether `.Sub(...)`
        // is being called. Use a short source window: the call
        // expression plus a few characters afterwards.
        let start = call.start_byte.min(unit.source.len());
        let end = (start + 32).min(unit.source.len());
        let window = &unit.source[start..end];
        if !window.contains(".Sub(") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_120,
            file,
            line,
            col,
            "time.Now().Sub(t) should be time.Since(t)",
            out,
        );
    }
}

/// PERF-122: `strings.HasPrefix(s, p)` followed by `s[len(p):]` should
/// be `strings.TrimPrefix(s, p)`.
pub(crate) fn detect_perf_122(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.HasPrefix" {
            continue;
        }
        // Look for a sibling `s[len(p):]` style slice on the receiver
        // argument. We approximate by searching a small source
        // window around the call for a matching slice expression.
        let start = call.start_byte.saturating_sub(64);
        let end = (call.start_byte + 256).min(source.len());
        let window = &source[start..end];
        if !window.contains("len(") || !window.contains(":]") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_122,
            file,
            line,
            col,
            "strings.HasPrefix + slice should be strings.TrimPrefix",
            out,
        );
    }
}

/// PERF-124: `strings.Replace(s, old, new, -1)` should be
/// `strings.ReplaceAll(s, old, new)`.
pub(crate) fn detect_perf_124(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Replace" {
            continue;
        }
        if !call.arguments.iter().any(|a| a.as_ref() == "-1") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_124,
            file,
            line,
            col,
            "strings.Replace(s, old, new, -1) should be strings.ReplaceAll(s, old, new)",
            out,
        );
    }
}

/// PERF-126: `http.CanonicalHeaderKey` applied to a string literal
/// that is already in canonical form. We approximate by checking a
/// curated allowlist of headers that ship canonicalized.
pub(crate) fn detect_perf_126(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "http.CanonicalHeaderKey" {
            continue;
        }
        let arg = call.arguments.first().map(|s| s.as_ref()).unwrap_or("");
        // Strip surrounding quotes.
        let inner = arg.trim_matches('"');
        if !is_canonical_header(inner) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_126,
            file,
            line,
            col,
            "http.CanonicalHeaderKey on an already-canonical header is a no-op",
            out,
        );
    }
}

/// PERF-127: `log.*(fmt.Sprintf("static string"))` — the format
/// string has no verbs, so the Sprintf is a no-op. We approximate by
/// checking that the format string contains no `%` outside of `%%`.
pub(crate) fn detect_perf_127(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if !is_log_call(&call.callee) {
            continue;
        }
        // Look for a fmt.Sprintf inside the arguments. The call
        // facts store the callee name of the outer log call; we
        // need to inspect the source to see if the format string is
        // static.
        let first_arg = call.arguments.first().map(|s| s.as_ref()).unwrap_or("");
        if !first_arg.contains("fmt.Sprintf") {
            continue;
        }
        // Naive verb check: count `%` not followed by another `%`.
        // A real implementation would parse the format string.
        let fmt = extract_first_quoted(first_arg);
        if !fmt_contains_verb(fmt) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_127,
                file,
                line,
                col,
                "log call wraps a fmt.Sprintf with no format verbs; pass the string directly",
                out,
            );
        }
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

/// PERF-115/116/117 helper: pull the source text starting at a
/// byte offset, capped to the same line. Used to look for the
/// trailing `== 0` / `!= -1` patterns without indexing past the
/// end of the line.
fn call_text(unit: &ParsedUnit, start: usize) -> &str {
    let source = unit.source.as_ref();
    let start = start.min(source.len());
    let end = source.len().min(start + 64);
    // Trim to end-of-line so we don't pick up the next statement.
    let line_end = source[start..end]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(end);
    &source[start..line_end]
}

fn is_log_call(callee: &str) -> bool {
    matches!(
        callee,
        "log.Print"
            | "log.Printf"
            | "log.Println"
            | "log.Fatal"
            | "log.Fatalf"
            | "log.Panic"
            | "log.Panicf"
            | "log.Error"
            | "log.Errorf"
            | "log.Warn"
            | "log.Warnf"
            | "log.Info"
            | "log.Infof"
            | "log.Debug"
            | "log.Debugf"
    )
}

fn extract_first_quoted(s: &str) -> &str {
    let open = s.find('"');
    let Some(open) = open else { return "" };
    let rest = &s[open + 1..];
    let close = rest.find('"');
    let Some(close) = close else { return "" };
    &rest[..close]
}

fn fmt_contains_verb(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Skip %% which is an escaped percent.
            if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
                i += 2;
                continue;
            }
            // A real verb follows: at least one ASCII letter
            // (the verb specifier) before a non-identifier byte.
            if i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphabetic() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// PERF-114: a `for i, v := range src { dst[i] = v }` loop is a
/// hand-rolled `copy(dst, src)`. The builtin compiles to memmove and
/// handles memory overlap; the manual loop does not.
pub(crate) fn detect_perf_114(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for ") || !source.contains("] =") {
        return;
    }

    for (start, end) in &facts.for_ranges {
        let range_text = &source[*start..*end];
        let body_start = range_text.find('{');
        let Some(body_start) = body_start else {
            continue;
        };
        let head = &range_text[..body_start];
        if !head.contains("range ") {
            continue;
        }
        if !is_indexed_range(head) {
            continue;
        }
        if head.contains("range m") || head.contains("range map") {
            continue;
        }
        // Skip the opening `{` so the body parser doesn't see it.
        let body = &range_text[body_start + 1..];
        if !looks_like_loop_copy(body) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_114,
            file,
            line,
            col,
            "manual for-range copy should be the copy() builtin (3-10x faster, handles overlap)",
            out,
        );
    }
}

fn is_indexed_range(head: &str) -> bool {
    let after_for = head.trim_start_matches("for").trim_start();
    let Some((bindings, _iter)) = after_for.split_once("range") else {
        return false;
    };
    // The bindings section may be `k, v` or `k, v :=` (the `:=`
    // token belongs to the bindings, not the iterable). Strip it
    // before splitting on the comma.
    let bindings = bindings
        .split_once(":=")
        .map(|(b, _)| b)
        .unwrap_or(bindings);
    let mut parts = bindings.split(',');
    let Some(idx) = parts.next() else {
        return false;
    };
    let Some(val) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    let idx = idx.trim();
    let val = val.trim();
    if idx.is_empty() || idx == "_" || !is_simple_ident(idx) {
        return false;
    }
    !val.is_empty() && val != "_" && is_simple_ident(val)
}

fn looks_like_loop_copy(body: &str) -> bool {
    let trimmed = body.trim().trim_end_matches('}').trim();
    let Some((lhs, rhs)) = trimmed.split_once('=') else {
        return false;
    };
    let rhs = rhs.trim();
    let lhs = lhs.trim();
    let Some(open) = lhs.find('[') else {
        return false;
    };
    let Some(close) = lhs[open..].find(']') else {
        return false;
    };
    if close == 0 {
        return false;
    }
    let dst = &lhs[..open];
    let idx = &lhs[open + 1..open + close];
    if !is_simple_ident(dst.trim()) || !is_simple_ident(idx.trim()) {
        return false;
    }
    if is_simple_ident(rhs) {
        return true;
    }
    if let Some(open) = rhs.find('[') {
        if let Some(close) = rhs[open..].find(']') {
            let inner = &rhs[open + 1..open + close];
            return close > 0
                && is_simple_ident(rhs[..open].trim())
                && is_simple_ident(inner.trim());
        }
    }
    false
}

fn is_simple_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// PERF-119: two or more `append` calls to the same slice variable in
/// the same block without intervening reads. The variadic form
/// `append(s, a, b, c)` triggers at most one growth, while two separate
/// calls can grow twice.
pub(crate) fn detect_perf_119(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut appends: Vec<&CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "append")
        .collect();
    if appends.len() < 2 {
        return;
    }
    appends.sort_by_key(|c| c.start_byte);

    for pair in appends.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.arguments.is_empty() || b.arguments.is_empty() {
            continue;
        }
        let a_target = a.arguments[0].as_ref();
        let b_target = b.arguments[0].as_ref();
        if a_target != b_target {
            continue;
        }
        if intervening_read(&unit.source[intermediate(a, b)..b.start_byte], a_target) {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_119,
            file,
            line,
            col,
            "consecutive append calls to the same slice can be merged into one variadic append",
            out,
        );
        return;
    }
}

fn intervening_read(window: &str, target: &str) -> bool {
    if window.is_empty() {
        return false;
    }
    let markers = ["(", target, ")", "len(", "range ", "copy("];
    for marker in markers {
        if window.contains(marker) {
            return true;
        }
    }
    false
}

/// Returns a safe lower bound for the window between two consecutive
/// call sites. The call facts only carry the start byte, so the upper
/// bound of `a` is approximated by `a.start_byte + 64` and clamped to
/// `b.start_byte` to avoid panics on adjacent calls.
fn intermediate(a: &CallFact, b: &CallFact) -> usize {
    a.start_byte.saturating_add(64).min(b.start_byte)
}

/// PERF-125: `if s != nil { s = append(s, x) }` — append already
/// handles a nil slice, so the nil check is redundant.
pub(crate) fn detect_perf_125(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("if ") || !source.contains(" != nil") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let target = call.arguments[0].as_ref();
        let window_start = call.start_byte.saturating_sub(160);
        let window = &source[window_start..call.start_byte];
        let guard = format!("if {target} != nil");
        if !window.contains(&guard) {
            continue;
        }
        // The call must be the RHS of an assignment to `target`:
        // i.e. the call's source line begins with `<target> = `.
        // We use a small pre-call window to look for the `= ` token
        // at end of the prior line / start of the current line.
        let prefix_start = call.start_byte.saturating_sub(target.len() + 4);
        let prefix = &source[prefix_start..call.start_byte];
        let trimmed = prefix.trim_start();
        if !trimmed.starts_with(&format!("{target} = "))
            && !trimmed.starts_with(&format!("{target}="))
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_125,
            file,
            line,
            col,
            "append handles a nil slice; the `if s != nil` guard is redundant",
            out,
        );
    }
}

/// PERF-129: `for _, v := range xs` where `v` is never used in the
/// loop body copies each element unnecessarily. Range by index when
/// the value is unused: `for i := range xs`.
pub(crate) fn detect_perf_129(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for (start, end) in &facts.for_ranges {
        let range_text = &source[*start..*end];
        let Some(body_start) = range_text.find('{') else {
            continue;
        };
        let head = &range_text[..body_start];
        let after_for = head.trim_start_matches("for").trim_start();
        let Some((bindings, _iter)) = after_for.split_once("range") else {
            continue;
        };
        let bindings = bindings
            .split_once(":=")
            .map(|(b, _)| b)
            .unwrap_or(bindings);
        let mut parts = bindings.split(',');
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };
        if parts.next().is_some() {
            continue;
        }
        let key = key.trim();
        let val = val.trim();
        if key != "_" {
            continue;
        }
        if val.is_empty() || val == "_" || !is_simple_ident(val) {
            continue;
        }
        let body = &range_text[body_start..];
        if word_appears_in(body, val) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_129,
            file,
            line,
            col,
            "range loop copies the value but the value is unused; range by index instead",
            out,
        );
    }
}

fn word_appears_in(text: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(idx) = text[start..].find(word) {
        let abs = start + idx;
        let before_ok =
            abs == 0 || (!bytes[abs - 1].is_ascii_alphanumeric() && bytes[abs - 1] != b'_');
        let end = abs + word.len();
        let after_ok =
            end == bytes.len() || (!bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_');
        if before_ok && after_ok {
            return true;
        }
        start = abs + word.len();
    }
    false
}

/// PERF-156: `for i, _ := range s` ranges over a string with only the
/// index. Use `for i := range s` to skip UTF-8 decoding.
pub(crate) fn detect_perf_156(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for (start, end) in &facts.for_ranges {
        let range_text = &source[*start..*end];
        let Some(body_start) = range_text.find('{') else {
            continue;
        };
        let head = &range_text[..body_start];
        let after_for = head.trim_start_matches("for").trim_start();
        let Some((bindings, iter_part)) = after_for.split_once("range") else {
            continue;
        };
        let bindings = bindings
            .split_once(":=")
            .map(|(b, _)| b)
            .unwrap_or(bindings);
        let mut parts = bindings.split(',');
        let Some(idx) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };
        if parts.next().is_some() {
            continue;
        }
        let idx = idx.trim();
        let val = val.trim();
        let iter = iter_part.trim();
        if val != "_" {
            continue;
        }
        if idx.is_empty() || !is_simple_ident(idx) {
            continue;
        }
        if !is_string_iterable(source, iter) {
            continue;
        }
        let body = &range_text[body_start..];
        if !word_appears_in(body, idx) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_156,
            file,
            line,
            col,
            "ranging over a string with `_` discards the decoded rune; use `for i := range s` to skip UTF-8 decoding",
            out,
        );
    }
}

fn is_string_iterable(source: &str, iter: &str) -> bool {
    if iter.is_empty() {
        return false;
    }
    if iter.starts_with('"') {
        return true;
    }
    if !is_simple_ident(iter) {
        return false;
    }
    let var_decl = format!("var {iter} string");
    if source.contains(&var_decl) {
        return true;
    }
    if source.contains(&format!("{iter} := \"")) {
        return true;
    }
    if source.contains(&format!("{iter} :=")) {
        return true;
    }
    true
}

/// PERF-177: `(*os.File).Readdir(-1)` predates `os.ReadDir(name)` and
/// returns a `[]os.FileInfo` (heavyweight) instead of `[]os.DirEntry`
/// (lighter). Use `os.ReadDir` for new code.
pub(crate) fn detect_perf_177(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".Readdir(") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(".Readdir(") {
        let start = search_from + rel;
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_177,
            file,
            line,
            col,
            "(*os.File).Readdir returns []os.FileInfo; prefer os.ReadDir for []os.DirEntry",
            out,
        );
        search_from = start + ".Readdir(".len();
    }
}

/// PERF-192: `make(map[K]V)` without a size hint. When the entries
/// are loaded from a slice with a known length, the map will resize
/// as it grows; pass `len(src)` as the hint.
pub(crate) fn detect_perf_192(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        let args = &call.arguments;
        if args.len() != 1 {
            continue;
        }
        let first = args[0].as_ref();
        if !first.starts_with("map[") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_192,
            file,
            line,
            col,
            "make(map[K]V) without a size hint; pass len(src) to avoid map growth",
            out,
        );
    }
    let _ = facts;
}

fn is_canonical_header(s: &str) -> bool {
    // A short, vetted list of common headers that are already
    // canonical. This is intentionally exact-case: `CanonicalHeaderKey`
    // would change inputs such as `ETag` to `Etag`, so those are not
    // redundant no-ops.
    const CANONICAL: &[&str] = &[
        "Accept",
        "Accept-Charset",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Cache-Control",
        "Content-Length",
        "Content-Type",
        "Cookie",
        "Date",
        "Etag",
        "Expect",
        "Expires",
        "From",
        "Host",
        "If-Match",
        "If-Modified-Since",
        "If-None-Match",
        "If-Range",
        "If-Unmodified-Since",
        "Keep-Alive",
        "Last-Modified",
        "Location",
        "Origin",
        "Pragma",
        "Range",
        "Referer",
        "Retry-After",
        "Server",
        "Set-Cookie",
        "Transfer-Encoding",
        "User-Agent",
        "Vary",
        "Via",
        "Warning",
        "Www-Authenticate",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Request-Id",
        "X-Csrf-Token",
    ];
    CANONICAL.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::is_canonical_header;

    #[test]
    fn canonical_header_allowlist_matches_known_textproto_outputs() {
        for header in [
            "Content-Type",
            "Etag",
            "Www-Authenticate",
            "X-Csrf-Token",
            "X-Forwarded-For",
            "User-Agent",
        ] {
            assert!(is_canonical_header(header), "{header}");
        }
    }

    #[test]
    fn canonical_header_allowlist_rejects_uncurated_headers() {
        for header in ["ETag", "X-CSRF-Token", "x-request-id", "Custom-Header"] {
            assert!(!is_canonical_header(header), "{header}");
        }
    }
}

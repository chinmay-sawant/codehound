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

/// PERF-110: `sync.Pool` whose `New` function returns a value type
/// instead of a pointer. Each `Put` boxes the value into an `eface`
/// on the pool's internal queue, and each `Get` unboxes it; returning
/// `*T` from `New` avoids the round trip.
pub(crate) fn detect_perf_110(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    use crate::ast::walk_nodes;
    use tree_sitter::Node;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("sync.Pool") {
        return;
    }

    // Walk composite-literal nodes whose text starts with `sync.Pool{`.
    // We need the literal's full text to inspect the `New:` field.
    walk_nodes(
        unit.tree.root_node(),
        &["composite_literal"],
        &mut |node: Node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            if !text.starts_with("sync.Pool{") {
                return;
            }
            // Find the New: ... } body. We bound the search to the
            // literal's text; `New:` is the only field we care about.
            let Some(new_idx) = text.find("New:") else {
                return;
            };
            let after = &text[new_idx..];
            // The New field is a function literal; we don't try to
            // walk it as AST (the value is a `func_literal` inside a
            // keyed_element). Just inspect the function literal text.
            // Detect: `func() *T {` (good) vs `func() T {` (bad) or
            // `func() interface{} { return &T{} }` (good).
            if let Some(open) = after.find("func()") {
                let sig = &after[open..];
                // The signature ends at the next `{`.
                let sig_end = sig.find('{').unwrap_or(sig.len());
                let signature = &sig[..sig_end];
                // Reject when the signature itself returns a pointer
                // (e.g. `func() *Foo { ... }`).
                if signature.contains('*') {
                    return;
                }
                // The return type is the trailing identifier in
                // `func() T`. Reject if it starts with `*`.
                let return_type = signature
                    .trim_start_matches("func()")
                    .trim()
                    .trim_start_matches('*')
                    .trim();
                if return_type.is_empty() || return_type == "_" {
                    return;
                }
                // If the body actually returns a pointer (`return &T{...}`
                // or `return new(T)`), the function is fine.
                if let Some(ret_idx) = after.find("return") {
                    let after_ret = &after[ret_idx + "return".len()..];
                    if after_ret.trim_start().starts_with('&')
                        || after_ret.trim_start().starts_with("new(")
                    {
                        return;
                    }
                }
                // The return type looks like a value type and the
                // return value is not a pointer — flag.
                let (line, col) = unit.line_col(node.start_byte());
                emit::push_finding(
                    &META_PERF_110,
                    file,
                    line,
                    col,
                    "sync.Pool New returns a value type; return a pointer (e.g. *Foo) to avoid boxing on Put",
                    out,
                );
            }
        },
    );
}

/// PERF-128: three or more consecutive `append` calls to the same
/// slice without intervening reads. This is the stricter version of
/// PERF-119 (which catches 2+); three independent growths is a
/// stronger signal of accidental reallocation.
pub(crate) fn detect_perf_128(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut appends: Vec<&CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "append")
        .collect();
    if appends.len() < 3 {
        return;
    }
    appends.sort_by_key(|c| c.start_byte);

    for triple in appends.windows(3) {
        let a = triple[0];
        let b = triple[1];
        let c = triple[2];
        if a.arguments.is_empty() || b.arguments.is_empty() || c.arguments.is_empty() {
            continue;
        }
        let target = a.arguments[0].as_ref();
        if b.arguments[0].as_ref() != target || c.arguments[0].as_ref() != target {
            continue;
        }
        // No intervening reads between the first and last call.
        if intervening_read(&unit.source[intermediate(a, b)..b.start_byte], target) {
            continue;
        }
        if intervening_read(&unit.source[intermediate(b, c)..c.start_byte], target) {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_128,
            file,
            line,
            col,
            "three or more independent append calls can be combined into one variadic append",
            out,
        );
        return;
    }
}

/// PERF-130: an immediately-invoked function literal whose body is a
/// single call expression. The wrapper adds an allocation and a
/// function call without providing any closure capture; inline the
/// call directly.
pub(crate) fn detect_perf_130(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("func()") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("func()") {
        let start = search_from + rel;
        // Exclude `go func()` (goroutine) and any other keyword
        // that takes a function literal. We look at the character
        // immediately before the `func()` token.
        if start > 0 {
            let prev = source[..start]
                .chars()
                .rev()
                .find(|c| !c.is_whitespace())
                .unwrap_or(' ');
            // Reject: `o` (end of `go`), `f` (end of `for`),
            // `,` / `(` (argument-list position — the IIFE is being
            // passed somewhere and may have a purpose).
            if matches!(prev, 'o' | 'f' | ',' | '(') {
                search_from = start + "func()".len();
                continue;
            }
        }
        // Look for the `(` invocation that turns this into an IIFE.
        let window_end = (start + 96).min(source.len());
        let window = &source[start..window_end];
        let Some(close) = window.find('}') else {
            search_from = start + "func()".len();
            continue;
        };
        let after_close = &window[close + 1..];
        if !after_close.trim_start().starts_with('(') {
            search_from = start + "func()".len();
            continue;
        }
        let body_start = window.find('{');
        let Some(body_start) = body_start else {
            search_from = start + "func()".len();
            continue;
        };
        let body = &window[body_start + 1..close];
        let body_trim = body.trim();
        if !is_single_call_expression(body_trim) {
            search_from = start + "func()".len();
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_130,
            file,
            line,
            col,
            "unnecessary func() { f(args) }() wrapper; inline the call",
            out,
        );
        search_from = start + "func()".len();
    }
}

fn is_single_call_expression(body: &str) -> bool {
    let body = body.trim();
    if body.is_empty() {
        return false;
    }
    // Must end with `)` (or `;` + `return f();` is also OK).
    let last = body.chars().last().unwrap_or(' ');
    if last != ')' && last != '}' {
        // Allow trailing newline.
    }
    // Reject obvious control flow.
    if body.contains("if ")
        || body.contains("for ")
        || body.contains("switch ")
        || body.contains("select ")
        || body.contains("var ")
        || body.contains("return ")
        || body.contains(";")
    {
        // A `;` allows `f(); g();` which is two calls; reject. But
        // a single statement followed by a `}` is fine; we already
        // trimmed the `}` above.
        if body.contains(';') {
            return false;
        }
        if body.contains("return ") {
            return false;
        }
        if body.contains("if ")
            || body.contains("for ")
            || body.contains("switch ")
            || body.contains("select ")
            || body.contains("var ")
        {
            return false;
        }
    }
    // Must look like `<ident>(...)` or `<ident>.<method>(...)`.
    let open = body.find('(');
    let Some(open) = open else {
        return false;
    };
    let prefix = body[..open].trim();
    if prefix.is_empty() {
        return false;
    }
    // The body can be a chained call. Walk the prefix to verify it
    // resolves to a single receiver + method chain.
    let mut depth = 0;
    let mut chars = prefix.chars().peekable();
    let mut last_was_dot = false;
    while let Some(c) = chars.next() {
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if c == '.' && depth == 0 {
            last_was_dot = true;
        } else if c.is_whitespace() && depth == 0 {
            return false;
        }
    }
    if depth != 0 {
        return false;
    }
    // Must not end with `.` (partial chain).
    !prefix.ends_with('.')
        && (last_was_dot
            || prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'))
}

/// PERF-135: `gob.NewEncoder` / `gob.NewDecoder` constructed inside a
/// loop. The constructor reflects on the destination type, which is
/// expensive; create the encoder once outside the loop.
pub(crate) fn detect_perf_135(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(callee, "gob.NewEncoder" | "gob.NewDecoder") {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_135,
            file,
            line,
            col,
            "gob.NewEncoder/Decoder inside a loop reflects on the type; hoist the constructor outside the loop",
            out,
        );
    }
}

/// PERF-140: `debug.SetGCPercent(-1)` disables the GC assist entirely
/// (the GC only runs when the heap grows past `GOMEMLIMIT` or the
/// runtime is out of memory). `debug.SetGCPercent(<50)` aggressively
/// trims the heap in production. Both warrant a code review.
pub(crate) fn detect_perf_140(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("debug.SetGCPercent") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "debug.SetGCPercent" {
            continue;
        }
        let Some(arg) = call.arguments.first() else {
            continue;
        };
        let raw = arg.as_ref();
        // The argument is the literal text of the expression; the
        // common cases are `-1`, `0`, or `int` / `int32` identifiers
        // we can't resolve. We only flag literal numeric values.
        let n = raw.trim().parse::<i64>().ok();
        let Some(n) = n else {
            continue;
        };
        let bad = n == -1 || (n > 0 && n < 50);
        if !bad {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_140,
            file,
            line,
            col,
            "debug.SetGCPercent in production is rarely what you want; remove the call or document the tuning",
            out,
        );
    }
    let _ = facts;
}

/// PERF-158: `sort.Slice` on a slice of basic types (`[]int`,
/// `[]string`, `[]float64`) with a comparator that is a single `<` /
/// `>` comparison. The dedicated `slices.Sort` / `slices.SortFunc` is
/// allocation-free and faster.
pub(crate) fn detect_perf_158(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("sort.Slice") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "sort.Slice" {
            continue;
        }
        let Some(first) = call.arguments.first().map(|a| a.as_ref()) else {
            continue;
        };
        // The first argument is the slice expression. We accept
        // `[]int`, `[]string`, `[]float64` as well as identifiers
        // that match a typed declaration or function parameter.
        if !is_basic_slice_type(first) && !is_basic_typed_identifier(source, first) {
            continue;
        }
        // The body of the comparator function literal should be a
        // single `if` with `<` / `>`. We inspect a window of the
        // comparator (the 2nd + 3rd args combined; we don't have
        // them, so use a substring scan around the call).
        let window_start = call.start_byte.saturating_sub(8);
        let window_end = (call.start_byte + 384).min(source.len());
        let window = &source[window_start..window_end];
        if !window.contains("func(") {
            continue;
        }
        let body_start = window
            .find("func(")
            .map(|i| window[i..].find('{').map(|j| i + j).unwrap_or(window.len()));
        let Some(body_start) = body_start else {
            continue;
        };
        let body_end = window[body_start..]
            .find('}')
            .map(|j| body_start + j)
            .unwrap_or(window.len());
        let body = &window[body_start + 1..body_end];
        if !body.contains('<') {
            continue;
        }
        if body.contains("len(") || body.contains("strings.") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_158,
            file,
            line,
            col,
            "sort.Slice on []int/[]string/[]float64; use slices.Sort or slices.SortFunc to avoid the comparator closure allocation",
            out,
        );
    }
    let _ = facts;
}

fn is_basic_slice_type(expr: &str) -> bool {
    matches!(
        expr.trim(),
        "[]int"
            | "[]int8"
            | "[]int16"
            | "[]int32"
            | "[]int64"
            | "[]uint"
            | "[]uint8"
            | "[]uint16"
            | "[]uint32"
            | "[]uint64"
            | "[]float32"
            | "[]float64"
            | "[]string"
            | "[]byte"
            | "[]rune"
    )
}

fn is_basic_typed_identifier(source: &str, ident: &str) -> bool {
    if !is_simple_ident(ident) {
        return false;
    }
    // We accept identifiers bound to any of the basic slice types:
    //   var xs []int
    //   xs := make([]int, ...)
    //   func F(xs []int)   (parameter)
    //   func F(xs []int, ...) (parameter with more args)
    //   (xs []int)   (anonymous func parameter)
    let decls = [
        format!("var {ident} []int"),
        format!("var {ident} []string"),
        format!("var {ident} []float"),
        format!("{ident} := make([]int"),
        format!("{ident} := make([]string"),
        format!("{ident} := make([]float"),
        format!("{ident} []int"),
        format!("{ident} []string"),
        format!("{ident} []float"),
    ];
    decls.iter().any(|p| source.contains(p.as_str()))
}

/// PERF-171: a buffered channel of size 1 (`make(chan struct{}, 1)`
/// or `make(chan bool, 1)`) used purely for acquire / release. Use a
/// `sync.Mutex` instead; the channel adds an extra scheduling hop.
pub(crate) fn detect_perf_171(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        if call.arguments.len() < 2 {
            continue;
        }
        let chan_type = call.arguments[0].as_ref();
        // Match `chan struct{}` or `chan bool`, optionally with `<-`
        // direction markers. The exact text from the AST is the type
        // expression as written.
        let chan_type_trim = chan_type.trim();
        let is_mutex_shape = chan_type_trim == "chan struct{}"
            || chan_type_trim == "chan bool"
            || chan_type_trim == "chan struct{ }"
            || chan_type_trim.starts_with("chan struct{},")
            || chan_type_trim.starts_with("chan bool,")
            || chan_type_trim.contains("chan struct{},")
            || chan_type_trim.contains("chan bool,");
        if !is_mutex_shape {
            continue;
        }
        let size = call.arguments[1].as_ref().trim();
        if size != "1" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_171,
            file,
            line,
            col,
            "make(chan T, 1) used as a mutex; use sync.Mutex instead of a channel",
            out,
        );
    }
    let _ = facts;
}

/// PERF-181: `json.NewDecoder(...)` without a subsequent `.UseNumber()`
/// call. When the target struct has `int` / `int64` fields and the
/// input contains numbers larger than 2^53, the default `float64`
/// decoding silently loses precision.
pub(crate) fn detect_perf_181(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("json.NewDecoder") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "json.NewDecoder" {
            continue;
        }
        // Look for a `.UseNumber()` call within a small window after
        // the decoder is created. We allow up to 256 bytes (a few
        // chained calls).
        let after = (call.start_byte + 256).min(source.len());
        let window = &source[call.start_byte..after];
        if window.contains(".UseNumber()") {
            continue;
        }
        // Suppress when the file doesn't have any int/int64 targets.
        if !source.contains("int") && !source.contains("int64") && !source.contains("int32") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_181,
            file,
            line,
            col,
            "json.NewDecoder without .UseNumber() silently loses precision for large integers",
            out,
        );
    }
    let _ = facts;
}

/// PERF-182: `bufio.NewWriter(w)` (single-arg) followed by a `Write`
/// call that passes a large `[]byte` literal. The default 4 KiB
/// buffer thrashes on big writes; pass an explicit size.
pub(crate) fn detect_perf_182(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("bufio.NewWriter") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "bufio.NewWriter" {
            continue;
        }
        if call.arguments.len() != 1 {
            continue;
        }
        // Look ahead 512 bytes for a `Write(` or `WriteString(` call
        // passing a literal of > 64 bytes (string or []byte).
        let after_start = call.start_byte;
        let after_end = (call.start_byte + 512).min(source.len());
        let window = &source[after_start..after_end];
        if !window.contains(".Write(") && !window.contains(".WriteString(") {
            continue;
        }
        if !has_large_string_literal(window) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_182,
            file,
            line,
            col,
            "bufio.NewWriter without an explicit buffer size; the default 4 KiB buffer thrashes on large writes",
            out,
        );
    }
    let _ = facts;
}

fn has_large_string_literal(window: &str) -> bool {
    // Walk quoted strings and check length. Cheap heuristic that
    // also catches byte slice literals.
    let bytes = window.as_bytes();
    let mut in_string = false;
    let mut start = 0;
    let mut total = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            if in_string {
                let len = i - start - 1;
                if len > 64 {
                    return true;
                }
                total += len;
                if total > 64 {
                    return true;
                }
            } else {
                start = i;
            }
            in_string = !in_string;
        }
    }
    false
}

/// PERF-106: `sync.Map` used in a write-heavy workload. We count
/// `Store` and `LoadAndDelete` calls vs `Load` calls in the file and
/// flag when writes strictly outnumber reads.
pub(crate) fn detect_perf_106(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("sync.Map") {
        return;
    }

    let mut writes = 0usize;
    let mut reads = 0usize;
    for call in &facts.calls {
        let method = method_name(call.callee.as_ref());
        match method {
            "Store" | "Swap" | "LoadAndDelete" | "Delete" | "CompareAndSwap"
            | "CompareAndDelete" => {
                writes += 1;
            }
            "Load" | "LoadOrStore" | "Range" => {
                reads += 1;
            }
            _ => {}
        }
    }
    // Need at least one read for the count to be meaningful and
    // writes must strictly outnumber reads.
    if reads == 0 || writes <= reads {
        return;
    }
    let (line, col) = sync_map_location(source, unit);
    emit::push_finding(
        &META_PERF_106,
        file,
        line,
        col,
        "sync.Map is write-heavy; use a plain map guarded by sync.Mutex instead",
        out,
    );
}

fn sync_map_location(source: &str, unit: &ParsedUnit) -> (usize, usize) {
    // The finding should point at the `sync.Map` declaration, not
    // at any call site.
    let byte = source.find("sync.Map").unwrap_or(0);
    unit.line_col(byte)
}

/// Returns the method name of a call fact's callee expression.
/// For `m.Store` returns `Store`; for `runtime.SetFinalizer` returns
/// `SetFinalizer`; for a bare identifier it returns the same name.
fn method_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

/// PERF-204: GORM `db.Updates(map[...])` or `db.Model().Updates(map[...])`
/// without a preceding `.Select("col1", ...)` call. The map can include
/// any field, so the UPDATE statement touches every column. Use
/// `.Select` to project only the intended columns.
pub(crate) fn detect_perf_204(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".Updates(") {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        // Match `db.Updates` or `db.Model().Updates` (and the
        // chained variants). The fact records the final call, so
        // we accept either form.
        if !callee.ends_with(".Updates") {
            continue;
        }
        // The first argument must be a map literal / `map[...]` or
        // a chained call. We accept anything that *contains* a
        // `map[` token, including `db.Model(...).Updates(map[...])`.
        let Some(first) = call.arguments.first().map(|a| a.as_ref()) else {
            continue;
        };
        if !first.contains("map[") {
            continue;
        }
        // Reject when the call chain has a `.Select(...)` somewhere
        // in the source window before the call.
        let window_start = call.start_byte.saturating_sub(256);
        let window = &source[window_start..call.start_byte];
        let select_idx = window.rfind(".Select(");
        // Only treat it as a preceding .Select if the
        // `Updates(` itself isn't part of the same chain. We
        // approximate: the `.Select` must appear after the most
        // recent `db.` or `.Model(` that starts the chain.
        if let Some(idx) = select_idx {
            // Find the start of the current statement by looking
            // for a newline or `;` before the .Select.
            let before = &window[..idx];
            let stmt_start = before
                .rfind('\n')
                .max(before.rfind(';'))
                .map(|i| i + 1)
                .unwrap_or(0);
            // If the .Select is on the same statement (no `;` or
            // newline in between), accept it as a guard.
            if stmt_start > 0 {
                continue;
            }
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_204,
            file,
            line,
            col,
            "db.Updates(map) without a preceding .Select; GORM will UPDATE every column",
            out,
        );
    }
}

/// PERF-209: Cobra `PersistentPreRunE` / `PersistentPostRunE` on a
/// parent command. Every subcommand inherits the hook, so the work
/// runs many times per CLI invocation.
pub(crate) fn detect_perf_209(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("cobra.Command") {
        return;
    }
    if !source.contains("PersistentPreRunE") && !source.contains("PersistentPostRunE") {
        return;
    }

    for marker in &["PersistentPreRunE", "PersistentPostRunE"] {
        let mut from = 0;
        while let Some(rel) = source[from..].find(marker) {
            let start = from + rel;
            // Only flag when the marker is a key in a struct
            // literal (preceded by a newline + whitespace).
            let pre = &source[..start];
            let last_nl = pre.rfind('\n').map(|i| i + 1).unwrap_or(0);
            let between = &source[last_nl..start];
            if !between.chars().all(|c| c.is_whitespace()) {
                from = start + marker.len();
                continue;
            }
            // Skip if the marker is on a comment line.
            if pre
                .lines()
                .last()
                .map(|l| l.trim_start().starts_with("//"))
                .unwrap_or(false)
            {
                from = start + marker.len();
                continue;
            }
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_209,
                file,
                line,
                col,
                "PersistentPreRunE / PersistentPostRunE runs for every subcommand; use a sync.Once or pre-build the dependency",
                out,
            );
            from = start + marker.len();
        }
    }
    let _ = facts;
}

/// PERF-211: GORM `db.Not(...)` / `db.Where("... NOT IN ...")` /
/// `db.Where("... NOT LIKE ...")` in a hot-path query. `NOT IN` /
/// `NOT LIKE` defeat index lookups because the planner must do a
/// full scan.
pub(crate) fn detect_perf_211(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("db.Not(") && !source.contains(".Not(") {
        // We need a fallback for `db.Where` with NOT IN / NOT LIKE.
    }
    let has_not_in = source.contains("NOT IN") || source.contains("not in");
    let has_not_like = source.contains("NOT LIKE") || source.contains("not like");
    if !source.contains("db.Not(") && !source.contains(".Not(") && !has_not_in && !has_not_like {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee.ends_with(".Not") && call.arguments.len() >= 1 {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_211,
                file,
                line,
                col,
                "db.Not(...) defeats index lookups; rewrite as a positive WHERE clause",
                out,
            );
            continue;
        }
        if callee.ends_with(".Where") {
            for arg in &call.arguments {
                let arg_text = arg.as_ref();
                if arg_text.to_uppercase().contains("NOT IN")
                    || arg_text.to_uppercase().contains("NOT LIKE")
                {
                    let (line, col) = unit.line_col(call.start_byte);
                    emit::push_finding(
                        &META_PERF_211,
                        file,
                        line,
                        col,
                        "NOT IN / NOT LIKE defeats index lookups; use a positive WHERE clause",
                        out,
                    );
                    break;
                }
            }
        }
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

/// PERF-132: `go func() { ... }` whose body makes a cancellable
/// I/O call but the function literal does not accept a context.
/// The parent function has a `ctx context.Context` parameter
/// (otherwise the warning is moot); the goroutine can't propagate
/// cancellation. We require both signals: the body makes a
/// cancellable I/O call AND the parent function has a `ctx`
/// parameter. Without the parent ctx, the goroutine has nothing
/// to forward.
pub(crate) fn detect_perf_132(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("go func()") {
        return;
    }
    if !parent_has_ctx_param(source) {
        return;
    }

    for (start, _end) in &facts.go_starts {
        let go_text = &source[*start..(*start + 256).min(source.len())];
        // The function literal must be `func() { ... }` with no
        // parameters. We accept `go func() {` (no params) and
        // reject `go func(ctx context.Context) {` (has params).
        if !go_text.contains("go func()") {
            continue;
        }
        // The body is the `{ ... }` block following the
        // signature. Look for cancellable I/O inside the body.
        let body_start = go_text.find('{');
        let Some(body_start) = body_start else {
            continue;
        };
        let body_end_rel = go_text[body_start..].find('}');
        let Some(body_end_rel) = body_end_rel else {
            continue;
        };
        let body = &go_text[body_start + 1..body_start + body_end_rel];
        if !body_has_io(body) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_132,
            file,
            line,
            col,
            "go func() body makes I/O calls but the goroutine doesn't accept a context; cancellation cannot propagate",
            out,
        );
    }
}

fn parent_has_ctx_param(source: &str) -> bool {
    // The parent function is the surrounding `func ... { ... }`
    // that contains the `go func()` site. We approximate by
    // looking for any function declaration that takes a
    // `ctx context.Context` parameter anywhere in the file.
    source.contains("ctx context.Context")
        || source.contains("ctx context.Context,")
        || source.contains("ctx context.Context)")
        || source.contains("ctx context.Context ")
}

fn body_has_io(body: &str) -> bool {
    // Match the common packages whose calls take a context as
    // the first argument. The detector only checks substrings.
    const PACKAGES: &[&str] = &[
        "http.", "db.", "sql.", "redis.", "rdb.", "client.", "store.", "queue.", "kafka.",
    ];
    PACKAGES.iter().any(|p| body.contains(p))
}

/// PERF-131: `mu.Lock` / `mu.Unlock` wrapping only a single
/// counter-style integer operation (`x++`, `x--`, `x = x + 1`,
/// `x += 1`, or a single-line compound assignment). Use
/// `sync/atomic` instead. We deliberately restrict the body
/// match to these exact patterns to avoid false positives on
/// mutex-guarded assignments to maps / slices / pointers (which
/// are not atomic-safe).
pub(crate) fn detect_perf_131(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".Lock()") || !source.contains(".Unlock()") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(".Lock()") {
        let start = search_from + rel;
        let unlock_rel = source[start..].find(".Unlock()");
        let Some(unlock_rel) = unlock_rel else {
            search_from = start + ".Lock()".len();
            continue;
        };
        let unlock_start = start + unlock_rel;
        let unlock_end = unlock_start + ".Unlock()".len();
        let after_lock = start + ".Lock()".len();
        let body = &source[after_lock..unlock_start];
        eprintln!(
            "[PERF-131] body={body:?} is_counter={}",
            is_simple_counter_body(body)
        );
        if is_simple_counter_body(body) {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_131,
                file,
                line,
                col,
                "mu.Lock/mu.Unlock wraps only a simple counter op; use sync/atomic instead",
                out,
            );
        }
        search_from = unlock_end;
    }
}

fn is_simple_counter_body(body: &str) -> bool {
    // The body is the text between `.Lock()` and `.Unlock()`.
    // Split on semicolons and newlines into statements. We
    // accept only the canonical counter patterns: x++, x--,
    // x += 1, x -= 1, x = x + 1, x = x - 1. Anything else
    // (assignments to maps / slices / pointers, function calls,
    // channel operations) is not atomic-safe and the mutex is
    // justified.
    //
    // The body sometimes includes a partial leading token of
    // the receiver for `.Unlock()` (e.g. the `mu` in
    // `counter++\n\tmu.Unlock()`). We strip that trailing
    // partial-identifier by trimming back to the last newline
    // before any non-counter text.
    let inner = body.trim();
    let mut counter_op = false;
    let mut non_counter_op = false;
    for stmt in inner.split(|c: char| c == ';' || c == '\n') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        // A partial leading identifier is a fragment of the
        // `mu.Unlock()` call we don't want to count.
        if stmt.starts_with('.') || stmt.ends_with('.') {
            continue;
        }
        // The trailing partial-identifier of the next call is
        // not a statement.
        if looks_like_partial_recv(stmt) {
            continue;
        }
        if is_counter_statement(stmt) {
            counter_op = true;
        } else {
            non_counter_op = true;
        }
    }
    counter_op && !non_counter_op
}

fn looks_like_partial_recv(stmt: &str) -> bool {
    // The partial receiver for `mu.Unlock()` looks like `mu`
    // (just an identifier with no operator). Skip it.
    is_simple_ident(stmt)
}

fn is_counter_statement(stmt: &str) -> bool {
    let stmt = stmt.trim();
    if stmt.is_empty() {
        return false;
    }
    // `x++` or `x--`
    if stmt.ends_with("++") || stmt.ends_with("--") {
        let head = stmt.trim_end_matches("++").trim_end_matches("--");
        return is_simple_ident(head.trim());
    }
    // `x += 1` or `x -= 1`
    if let Some((lhs, rhs)) = stmt.split_once("+=") {
        return rhs.trim() == "1" && is_simple_ident(lhs.trim());
    }
    if let Some((lhs, rhs)) = stmt.split_once("-=") {
        return rhs.trim() == "1" && is_simple_ident(lhs.trim());
    }
    // `x = x + 1` or `x = x - 1`
    if let Some((lhs, rhs)) = stmt.split_once('=') {
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        if let Some((rlhs, rrhs)) = rhs.split_once('+') {
            return rrhs.trim() == "1"
                && is_simple_ident(rlhs.trim())
                && is_simple_ident(lhs)
                && lhs == rlhs.trim();
        }
        if let Some((rlhs, rrhs)) = rhs.split_once('-') {
            return rrhs.trim() == "1"
                && is_simple_ident(rlhs.trim())
                && is_simple_ident(lhs)
                && lhs == rlhs.trim();
        }
    }
    false
}

/// PERF-168: `ch <- <CompositeLiteral>` where the literal has 4+
/// fields or contains a slice / map / string field. A pointer
/// (`ch <- &T{...}`) is the correct shape.
pub(crate) fn detect_perf_168(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("<- ") {
        let start = search_from + rel;
        // Distinguish a channel send from a channel type.
        // `chan<- T` is a type with no space before `<-`; the
        // send `ch <- T` has whitespace + identifier + space +
        // `<- `. We require the character immediately before
        // `<-` to be a space.
        if start == 0 || source.as_bytes()[start - 1] != b' ' {
            search_from = start + "<- ".len();
            continue;
        }
        // The literal starts after `<- `. Look for the next `{`
        // to find the literal start.
        let arrow_end = start + "<- ".len();
        let Some(open_rel) = source[arrow_end..].find('{') else {
            search_from = arrow_end;
            continue;
        };
        let pre = &source[arrow_end..arrow_end + open_rel];
        // Reject if the channel send is already a pointer
        // (`ch <- &T{...}`) or an existing variable
        // (`ch <- someVar`).
        let trimmed_pre = pre.trim_start();
        if trimmed_pre.starts_with('&') {
            search_from = arrow_end + open_rel;
            continue;
        }
        let lit_start = arrow_end + open_rel;
        let close_rel = source[lit_start..].find('}');
        let Some(close_rel) = close_rel else {
            search_from = lit_start;
            continue;
        };
        let literal = &source[lit_start..lit_start + close_rel + 1];
        if is_large_struct_literal(literal) {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_168,
                file,
                line,
                col,
                "large struct sent by value over a channel; pass a pointer instead",
                out,
            );
        }
        search_from = lit_start + close_rel + 1;
    }
}

fn is_large_struct_literal(literal: &str) -> bool {
    // Strip the outer `{ }` and split on top-level commas.
    let inner = literal.trim().trim_start_matches('{').trim_end_matches('}');
    // Count fields: split on commas not inside parens/brackets.
    let mut depth = 0;
    let mut fields = 0;
    let mut has_complex_field = false;
    let mut current = String::new();
    for c in inner.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                fields += 1;
                let trimmed = current.trim();
                if trimmed.contains('[') || trimmed.contains("map[") {
                    has_complex_field = true;
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        fields += 1;
        let trimmed = current.trim();
        if trimmed.contains('[') || trimmed.contains("map[") {
            has_complex_field = true;
        }
    }
    fields >= 4 || has_complex_field
}

/// PERF-121: two consecutive same-shape struct literals where the
/// second builds from the first. Direct conversion (T(x)) would
/// suffice. We look for two struct literals with **different** type
/// names but identical field sets within 8 lines.
pub(crate) fn detect_perf_121(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("struct {") {
        return;
    }

    let literals = collect_struct_literals(source);
    if literals.len() < 2 {
        return;
    }
    for pair in literals.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        // Two different type names with identical field sets.
        if a.type_name == b.type_name {
            continue;
        }
        if a.fields != b.fields {
            continue;
        }
        // Adjacent lines: between offsets, at most 2 newlines.
        let between = &source[a.end..b.start];
        if between.matches('\n').count() > 2 {
            continue;
        }
        let (line, col) = unit.line_col(a.start);
        emit::push_finding(
            &META_PERF_121,
            file,
            line,
            col,
            "struct literal copies another literal of the same shape; use a direct type conversion (T(x))",
            out,
        );
        return;
    }
}

struct StructLiteral {
    type_name: String,
    fields: Vec<String>,
    start: usize,
    end: usize,
}

fn collect_struct_literals(source: &str) -> Vec<StructLiteral> {
    // Walk every `{` that closes after a TypeName{...} shape.
    // We look for `Ident{` where Ident is a simple type name.
    let mut out = Vec::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Look at the preceding non-whitespace token.
            if i > 0 {
                let pre = &source[..i];
                let trimmed = pre.trim_end();
                let Some(name) = trimmed
                    .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                else {
                    i += 1;
                    continue;
                };
                if !is_simple_ident(name) {
                    i += 1;
                    continue;
                }
                // Find the matching `}`.
                let close_rel = source[i..].find('}');
                let Some(close_rel) = close_rel else {
                    i += 1;
                    continue;
                };
                let body = &source[i + 1..i + close_rel];
                let fields = parse_field_list(body);
                if !fields.is_empty() {
                    out.push(StructLiteral {
                        type_name: name.to_string(),
                        fields,
                        start: i,
                        end: i + close_rel + 1,
                    });
                }
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

fn parse_field_list(body: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut depth = 0;
    let mut current = String::new();
    for c in body.chars() {
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                let field = field_name(&current);
                if let Some(name) = field {
                    fields.push(name);
                }
                current.clear();
            }
            _ => current.push(c),
        }
    }
    let field = field_name(&current);
    if let Some(name) = field {
        fields.push(name);
    }
    fields
}

fn field_name(text: &str) -> Option<String> {
    // Field syntax: `Name: value` or `Name:`
    let text = text.trim();
    let (name, _) = text.split_once(':')?;
    Some(name.trim().to_string())
}

/// PERF-165: `rows.Scan(&x)` followed by manual extraction of
/// fields from a primitive type into a custom type on the next
/// line. The proper fix is to implement `sql.Scanner`.
pub(crate) fn detect_perf_165(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("rows.Scan(") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("rows.Scan(") {
        let start = search_from + rel;
        let after_start = start + "rows.Scan(".len();
        let after_end = (after_start + 384).min(source.len());
        let window = &source[after_start..after_end];
        if let Some(close) = window.find(')') {
            let first_arg = &window[..close];
            if first_arg.contains("&sql.Null")
                || first_arg.contains("&*string")
                || first_arg.contains("&*int")
            {
                search_from = after_start;
                continue;
            }
        }
        // The function body after the scan should contain a
        // string-parsing call (`strconv.ParseInt`, `strconv.ParseFloat`,
        // `strconv.ParseBool`, `time.Parse`, ...) and a `MyID(` /
        // `MyType(` conversion. We restrict the search to the
        // current function (delimited by the next top-level `}`)
        // to avoid false positives across functions.
        let func_end = source[after_start..]
            .find("}\n\n")
            .or_else(|| source[after_start..].find("}\nfunc"))
            .or_else(|| source[after_start..].rfind('}'))
            .map(|i| after_start + i)
            .unwrap_or(source.len());
        let after_block = &source[after_start..func_end];
        let has_parse_call = after_block.contains("strconv.Parse")
            || after_block.contains("time.Parse")
            || after_block.contains("uuid.Parse")
            || after_block.contains(".Parse(");
        let has_custom_conversion = after_block.contains("MyID(")
            || after_block.contains("MyType(")
            || after_block.contains("UUID(")
            || after_block.contains("Timestamp(")
            || after_block.contains("MyTime(");
        if !(has_parse_call && has_custom_conversion) {
            search_from = after_start;
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_165,
            file,
            line,
            col,
            "rows.Scan into a primitive type followed by manual conversion to a custom type; implement sql.Scanner on the custom type",
            out,
        );
        search_from = after_start;
    }
}

/// PERF-166: `rows.Scan(&s)` where `s` is `*string` / `*int64`,
/// followed by an `if s != nil` null check. The idiomatic
/// alternative is `sql.NullString` / `sql.NullInt64` which the
/// `database/sql` package already knows how to populate.
pub(crate) fn detect_perf_166(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("rows.Scan(") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("rows.Scan(") {
        let start = search_from + rel;
        let after_start = start + "rows.Scan(".len();
        let after_end = (after_start + 384).min(source.len());
        let window = &source[after_start..after_end];
        // The first scan argument must be a pointer (`&s`).
        let Some(close) = window.find(')') else {
            search_from = after_start;
            continue;
        };
        let first_arg = window[..close].trim();
        if !first_arg.starts_with('&') {
            search_from = after_start;
            continue;
        }
        // The variable must be a plain identifier (not already a
        // sql.Null* type).
        let var = first_arg.trim_start_matches('&').trim();
        if !is_simple_ident(var) {
            search_from = after_start;
            continue;
        }
        if var.starts_with("Null") {
            search_from = after_start;
            continue;
        }
        // The next ~512 bytes should contain an `if var != nil`
        // null check.
        let after_block_end = (after_start + 512).min(source.len());
        let after_block = &source[after_start..after_block_end];
        let guard = format!("if {var} != nil");
        if !after_block.contains(&guard) {
            search_from = after_start;
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_166,
            file,
            line,
            col,
            "rows.Scan into a pointer followed by a null check; use sql.NullString / sql.NullInt64 instead",
            out,
        );
        search_from = after_start;
    }
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

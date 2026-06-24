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
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

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

fn is_canonical_header(s: &str) -> bool {
    // A short, vetted list of common headers that are already
    // canonical. The Go stdlib's `http.CanonicalHeaderKey` is a
    // case-insensitive match: every header below is what
    // CanonicalHeaderKey would return.
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
    CANONICAL.iter().any(|h| h.eq_ignore_ascii_case(s))
}

//! PERF-105, 111, 112, 115, 116, 117, 119, 124, 125, 130: strings/bytes misuse.

use super::common::{call_text, is_simple_ident};
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::{CallFact, GoPerfFacts};
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

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

pub(crate) fn intervening_read(window: &str, target: &str) -> bool {
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
pub(crate) fn intermediate(a: &CallFact, b: &CallFact) -> usize {
    a.start_byte.saturating_add(64).min(b.start_byte)
}

/// PERF-125: `if s != nil { s = append(s, x) }` — append already
/// handles a nil slice, so the nil check is redundant.
pub(crate) fn detect_perf_125(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("if ") || !facts.source_index.has(" != nil") {
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

/// PERF-130: an immediately-invoked function literal whose body is a
/// single call expression. The wrapper adds an allocation and a
/// function call without providing any closure capture; inline the
/// call directly.
pub(crate) fn detect_perf_130(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("func()") {
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
    for c in chars.by_ref() {
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

// Helpers used by ranges_and_types

pub(crate) fn is_indexed_range(head: &str) -> bool {
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

pub(crate) fn looks_like_loop_copy(body: &str) -> bool {
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
    if let Some(open) = rhs.find('[')
        && let Some(close) = rhs[open..].find(']')
    {
        let inner = &rhs[open + 1..open + close];
        return close > 0 && is_simple_ident(rhs[..open].trim()) && is_simple_ident(inner.trim());
    }
    false
}

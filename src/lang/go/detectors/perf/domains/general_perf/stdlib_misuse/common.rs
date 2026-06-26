//! Shared helpers used by multiple stdlib_misuse sub-files.
//!
//! All helpers are `pub(crate)` so sibling modules under
//! `stdlib_misuse/` can access them via `super::common::*`.

use crate::core::ParsedUnit;

/// PERF-115/116/117 helper: pull the source text starting at a
/// byte offset, capped to the same line. Used to look for the
/// trailing `== 0` / `!= -1` patterns without indexing past the
/// end of the line.
pub(crate) fn call_text(unit: &ParsedUnit, start: usize) -> &str {
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

pub(crate) fn is_log_call(callee: &str) -> bool {
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

pub(crate) fn extract_first_quoted(s: &str) -> &str {
    let open = s.find('"');
    let Some(open) = open else { return "" };
    let rest = &s[open + 1..];
    let close = rest.find('"');
    let Some(close) = close else { return "" };
    &rest[..close]
}

pub(crate) fn fmt_contains_verb(s: &str) -> bool {
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

/// Returns the method name of a call fact's callee expression.
/// For `m.Store` returns `Store`; for `runtime.SetFinalizer` returns
/// `SetFinalizer`; for a bare identifier it returns the same name.
pub(crate) fn method_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

pub(crate) fn is_simple_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(crate) fn body_has_io(body: &str) -> bool {
    // Match the common packages whose calls take a context as
    // the first argument. The detector only checks substrings.
    const PACKAGES: &[&str] = &[
        "http.", "db.", "sql.", "redis.", "rdb.", "client.", "store.", "queue.", "kafka.",
    ];
    PACKAGES.iter().any(|p| body.contains(p))
}

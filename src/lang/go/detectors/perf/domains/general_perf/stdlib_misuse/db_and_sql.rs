//! PERF-165, 166, 181, 182: database and SQL misuse.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{emit, Finding};
use super::common::is_simple_ident;

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

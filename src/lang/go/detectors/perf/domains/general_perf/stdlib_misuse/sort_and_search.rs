//! PERF-108, 133, 156, 158, 177: sort, search, and I/O misuse.

use super::common::is_simple_ident;
use super::ranges_and_types::{is_string_iterable, word_appears_in};
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::is_in_loop;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-108: `sort.Search` inside a loop. Binary search is the
/// whole point of caching; calling it per iteration is wasted
/// work.
pub(crate) fn detect_perf_108(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "sort.Search" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_108,
            file,
            line,
            col,
            "sort.Search inside a loop; hoist the search or use a different data structure",
            out,
        );
    }
}

/// PERF-133: `sort.Slice` with a closure inside a loop. The
/// closure allocates per call; use a `sort.Interface` type.
pub(crate) fn detect_perf_133(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "sort.Slice" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_133,
            file,
            line,
            col,
            "sort.Slice inside a loop allocates a comparator closure per call; hoist the sort or use slices.SortFunc",
            out,
        );
    }
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

/// PERF-158: `sort.Slice` on a slice of basic types (`[]int`,
/// `[]string`, `[]float64`) with a comparator that is a single `<` /
/// `>` comparison. The dedicated `slices.Sort` / `slices.SortFunc` is
/// allocation-free and faster.
pub(crate) fn detect_perf_158(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("sort.Slice") {
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

/// PERF-177: `(*os.File).Readdir(-1)` predates `os.ReadDir(name)` and
/// returns a `[]os.FileInfo` (heavyweight) instead of `[]os.DirEntry`
/// (lighter). Use `os.ReadDir` for new code.
pub(crate) fn detect_perf_177(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has(".Readdir(") {
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

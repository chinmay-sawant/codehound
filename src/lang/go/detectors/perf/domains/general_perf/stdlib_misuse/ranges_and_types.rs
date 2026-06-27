//! PERF-113, 114, 121, 146, 147, 157: ranges, types, and fmt misuse.

use super::common::is_simple_ident;
use super::strings_bytes::{is_indexed_range, looks_like_loop_copy};
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

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

/// PERF-114: a `for i, v := range src { dst[i] = v }` loop is a
/// hand-rolled `copy(dst, src)`. The builtin compiles to memmove and
/// handles memory overlap; the manual loop does not.
pub(crate) fn detect_perf_114(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("for ") || !facts.source_index.has("] =") {
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

/// PERF-121: two consecutive same-shape struct literals where the
/// second builds from the first. Direct conversion (T(x)) would
/// suffice. We look for two struct literals with **different** type
/// names but identical field sets within 8 lines.
pub(crate) fn detect_perf_121(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("struct {") {
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

// Helpers used by maps_and_slices and sort_and_search

pub(crate) fn word_appears_in(text: &str, word: &str) -> bool {
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

pub(crate) fn is_string_iterable(source: &str, iter: &str) -> bool {
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

// Helper used by sync_and_locks

pub(crate) fn is_large_struct_literal(literal: &str) -> bool {
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

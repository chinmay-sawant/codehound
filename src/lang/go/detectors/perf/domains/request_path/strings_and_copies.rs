use super::super::super::common::is_assignment_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use super::is_request_handler;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-017: string concatenation per request body parsing.
pub(crate) fn detect_perf_17(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_handler(&facts.source_index) {
        return;
    }

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !expr.contains("strings.Join(") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_17,
            file,
            line,
            col,
            "strings.Join is invoked inside a loop on a request path",
            out,
        );
    }
}

/// PERF-018: unnecessary full-slice copy via `append(dst, src...)`.
///
/// Classic shape: `dst := make([]T, 0, len(src)); dst = append(dst, src...)`
/// — a full copy when the caller could often keep/reslice the original.
pub(crate) fn detect_perf_18(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        let Some((dst, src)) = parse_append_spread(expr) else {
            continue;
        };
        // Only the classic full-copy pattern:
        //   dst := make([]T, 0, len(src))
        //   dst = append(dst, src...)
        // Accumulating append(dst, batch...) with a fixed/other cap is fine.
        if !source.contains(&format!("0, len({src})")) {
            continue;
        }
        if !source.contains(&format!("append({dst}, {src}...)")) {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_18,
            file,
            line,
            col,
            "large slice is copied via append(dst, src...) where ownership transfer or reslicing may suffice",
            out,
        );
        return;
    }
}

/// Parse `append(dst, src...)` / `append(dst, src ...)` → (dst, src).
fn parse_append_spread(expr: &str) -> Option<(&str, &str)> {
    let rest = expr.trim();
    let rest = rest.strip_prefix("append(")?;
    let rest = rest.strip_suffix(')')?;
    let (dst, after) = rest.split_once(',')?;
    let after = after.trim();
    let src = after.strip_suffix("...")?.trim();
    let dst = dst.trim();
    if dst.is_empty() || src.is_empty() {
        return None;
    }
    if !dst.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    if !src.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((dst, src))
}

/// PERF-019: range over slice of large structs by value.
pub(crate) fn detect_perf_19(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("for _, record := range records") {
        return;
    }
    if !facts.source_index.has("processRecord(record)") {
        return;
    }
    if facts.source_index.has("for _, record := range &records")
        || facts.source_index.has("for _, record := range recordsPtr")
    {
        return;
    }

    let start = source.find("for _, record := range records").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_19,
        file,
        line,
        col,
        "range over a slice of large structs copies each element by value",
        out,
    );
}

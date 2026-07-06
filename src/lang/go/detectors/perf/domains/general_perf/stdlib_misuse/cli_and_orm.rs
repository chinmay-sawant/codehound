//! PERF-204, 209, 211: CLI and ORM misuse.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-204: GORM `db.Updates(map[...])` or `db.Model().Updates(map[...])`
/// without a preceding `.Select("col1", ...)` call. The map can include
/// any field, so the UPDATE statement touches every column. Use
/// `.Select` to project only the intended columns.
pub(crate) fn detect_perf_204(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has(".Updates(") {
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

    if !facts.source_index.has("cobra.Command") {
        return;
    }
    if !facts.source_index.has("PersistentPreRunE") && !facts.source_index.has("PersistentPostRunE")
    {
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
}

/// PERF-211: GORM `db.Not(...)` / `db.Where("... NOT IN ...")` /
/// `db.Where("... NOT LIKE ...")` in a hot-path query. `NOT IN` /
/// `NOT LIKE` defeat index lookups because the planner must do a
/// full scan.
pub(crate) fn detect_perf_211(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !facts.source_index.has("db.Not(") && !facts.source_index.has(".Not(") {
        // We need a fallback for `db.Where` with NOT IN / NOT LIKE.
    }
    let has_not_in = facts.source_index.has("NOT IN") || facts.source_index.has("not in");
    let has_not_like = facts.source_index.has("NOT LIKE") || facts.source_index.has("not like");
    if !facts.source_index.has("db.Not(")
        && !facts.source_index.has(".Not(")
        && !has_not_in
        && !has_not_like
    {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee.ends_with(".Not") && !call.arguments.is_empty() {
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

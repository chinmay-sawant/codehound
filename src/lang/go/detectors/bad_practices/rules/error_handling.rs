//! BP-1, BP-2, BP-4, BP-5 — error-handling bad practices.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::{line_start_byte, push_at};
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// BP-1: discarded error-shaped return via `_`.
///
/// Flags:
/// - `_ = call(...)` when the call is not a known non-error builtin
/// - `x, _ := call(...)` / `_, _ := call(...)` (typical discarded `error`)
///
/// Does **not** flag non-call discards (`_ = x`) or pure builtins (`_ = len(s)`).
pub(crate) fn detect_bp_1_discarded_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn walk(node: Node, src: &[u8], file: &str, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if node.kind() == "assignment_statement" || node.kind() == "short_var_declaration" {
            if let Ok(text) = node.utf8_text(src) {
                if let Some((lhs, rhs)) = split_assign(text) {
                    if rhs.contains('(')
                        && !is_non_error_builtin_rhs(rhs)
                        && lhs_discards_possible_error(lhs)
                    {
                        let (line, col) = unit.line_col(node.start_byte());
                        emit::push_finding(
                            &crate::lang::go::detectors::bad_practices::BP_1_META,
                            file,
                            line,
                            col,
                            "discarded error return; handle or explicitly ignore with a comment",
                            out,
                        );
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out);
        }
    }

    walk(root, src, file, unit, out);
}

fn split_assign(text: &str) -> Option<(&str, &str)> {
    text.split_once(":=")
        .or_else(|| text.split_once('='))
        .map(|(l, r)| (l.trim(), r.trim()))
}

fn lhs_discards_possible_error(lhs: &str) -> bool {
    let names: Vec<&str> = lhs.split(',').map(str::trim).collect();
    let has_blank = names.contains(&"_");
    let binds_err = names
        .iter()
        .any(|n| *n == "err" || *n == "error" || n.ends_with("Err"));
    has_blank && !binds_err
}

/// Builtins / helpers that are not error-returning (or not errcheck targets).
fn is_non_error_builtin_rhs(rhs: &str) -> bool {
    let t = rhs.trim();
    let name = t
        .split('(')
        .next()
        .unwrap_or(t)
        .rsplit('.')
        .next()
        .unwrap_or(t)
        .trim();
    matches!(
        name,
        "len"
            | "cap"
            | "append"
            | "make"
            | "new"
            | "copy"
            | "delete"
            | "clear"
            | "min"
            | "max"
            | "real"
            | "imag"
            | "complex"
            | "close"
            | "panic"
            | "recover"
            | "print"
            | "println"
    )
}

/// BP-2: `return err` without contextual wrapping.
pub(crate) fn detect_bp_2_naked_error_return(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    for (idx, line) in unit.source.lines().enumerate() {
        if line.trim() == "return err" {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_2_META,
                line_start_byte(unit.source.as_ref(), idx),
                "naked return err loses operation context; wrap it before returning",
            );
        }
    }
}

/// BP-4: `recover()` without nearby logging or explicit reporting.
pub(crate) fn detect_bp_4_recover_without_logging(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !index.has("recover()") {
        return;
    }
    let reports_recovery = index.has("log.")
        || index.has("Logger.")
        || index.has(".Error(")
        || index.has(".Warn(")
        || index.has("fmt.Printf(")
        || index.has("fmt.Fprintf(");
    if reports_recovery {
        return;
    }
    if let Some(pos) = source.find("recover()") {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_4_META,
            pos,
            "recover() suppresses panic information without logging or reporting it",
        );
    }
}

/// BP-5: Close() errors ignored through bare or deferred calls.
pub(crate) fn detect_bp_5_ignored_close_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.contains(".Close()") {
            continue;
        }
        let handled = trimmed.contains("if err :=")
            || trimmed.contains("if closeErr :=")
            || trimmed.contains("= ")
            || trimmed.starts_with("_ =");
        if !handled || trimmed.starts_with("defer ") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_5_META,
                line_start_byte(source, idx) + line.find(".Close()").unwrap_or(0),
                "Close() return value is ignored; check the close error where it can affect correctness",
            );
        }
    }
}

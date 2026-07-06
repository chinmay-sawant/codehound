use super::super::super::common::is_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-014: filepath.Glob / os.ReadDir inside a loop.
pub(crate) fn detect_perf_14(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = ["filepath.Glob", "os.ReadDir", "ioutil.ReadDir"];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_14,
            file,
            line,
            col,
            "directory scan is performed inside a loop body",
            out,
        );
    }
}

/// PERF-015: strconv formatting inside a loop.
pub(crate) fn detect_perf_15(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = [
        "strconv.Itoa",
        "strconv.FormatInt",
        "strconv.FormatUint",
        "strconv.FormatFloat",
    ];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        if call.callee.as_ref() == "strconv.AppendInt"
            || call.callee.as_ref() == "strconv.AppendUint"
            || call.callee.as_ref() == "strconv.AppendFloat"
        {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_15,
            file,
            line,
            col,
            "strconv formatting is performed inside a loop body",
            out,
        );
    }
}

/// PERF-016: bytes.Buffer{} or new(bytes.Buffer) inside a loop.
pub(crate) fn detect_perf_16(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("bytes.Buffer{}") && !facts.source_index.has("new(bytes.Buffer)") {
        return;
    }
    if !facts.source_index.has("bytes.Buffer{") {
        return;
    }

    walk_nodes(
        unit.tree.root_node(),
        &["composite_literal", "unary_expression"],
        &mut |node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            if text != "bytes.Buffer{}" && text != "new(bytes.Buffer)" {
                return;
            }
            let mut current = node;
            let mut in_loop = false;
            while let Some(parent) = current.parent() {
                if parent.kind() == "for_statement" {
                    in_loop = true;
                    break;
                }
                current = parent;
            }
            if !in_loop {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_16,
                file,
                line,
                col,
                "bytes.Buffer is allocated inside a loop body",
                out,
            );
        },
    );
}

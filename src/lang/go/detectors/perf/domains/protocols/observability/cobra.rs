#![allow(dead_code)]
//! PERF-100: Cobra CLI performance detector.

use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-100: cobra.Command with heavy RunE (large init, repeated flag
/// registration).
pub(crate) fn detect_perf_100(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has_any(COBRA_MARKERS) {
        return;
    }
    let mut flag_count = 0usize;
    let mut first_start: Option<usize> = None;
    walk_nodes(unit.tree.root_node(), &["call_expression"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !is_flag_call(text) {
            return;
        }
        if first_start.is_none() {
            first_start = Some(node.start_byte());
        }
        flag_count += 1;
    });
    if flag_count < 4 {
        return;
    }
    if let Some(start) = first_start {
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_100,
            file,
            line,
            col,
            "cobra.Command registers many flags inline; defer heavy init to PersistentPreRunE or a sync.Once to keep CLI startup fast",
            out,
        );
    }
}

//! Fact extraction for Go PERF heuristics.
//!
//! Each detector receives a [`GoPerfFacts`] summary that fuses a single
//! tree-sitter walk with a substring index. The same call / assignment facts
//! the CWE bundle uses are reused here, so the cost is one extra walk per file
//! rather than one per detector.

use std::collections::HashMap;
use std::sync::Arc;

use tree_sitter::Node;

use crate::ast::{walk_calls_and_assignments};
use crate::core::ParsedUnit;

use super::source_index::PerfSourceIndex;

type SharedText = Arc<str>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: SharedText,
    pub arguments: Box<[SharedText]>,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: SharedText,
    pub expr: SharedText,
    /// Full text of the assignment node, including any compound-assignment
    /// operator (e.g. `s += strconv.Itoa(v)`). Detectors that care about the
    /// operator consult this instead of reconstructing it from `name` + `expr`.
    pub text: SharedText,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GoPerfFacts {
    pub calls: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    /// Single-pass substring flags for hot detector guards.
    pub source_index: PerfSourceIndex,
}

pub fn build_go_perf_facts(unit: &ParsedUnit) -> GoPerfFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoPerfFacts::default();
    let mut interner = SharedTextInterner::default();

    walk_calls_and_assignments(root, &mut |node| match node.kind() {
        "call_expression" | "call" => {
            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let Ok(callee) = func.utf8_text(src) else {
                return;
            };

            let arguments = node
                .child_by_field_name("arguments")
                .map(|args| extract_argument_texts(args, src, &mut interner))
                .unwrap_or_default();

            facts.calls.push(CallFact {
                callee: interner.intern(callee),
                arguments,
                start_byte: node.start_byte(),
                enclosing_loop: enclosing_loop_start(node),
            });
        }
        "assignment_statement" | "short_var_declaration" => {
            let Ok(text) = node.utf8_text(src) else {
                return;
            };
            let Some((lhs, rhs)) = split_assignment(text) else {
                return;
            };
            for name in extract_identifiers(lhs) {
                if name.is_empty() {
                    continue;
                }
                facts.assignments.push(AssignmentFact {
                    name: interner.intern(name),
                    expr: interner.intern(rhs),
                    text: interner.intern(text),
                    start_byte: node.start_byte(),
                    enclosing_loop: enclosing_loop_start(node),
                });
            }
        }
        _ => {}
    });

    facts.source_index = PerfSourceIndex::build(unit.source.as_ref());
    facts
}

/// Returns the start byte of the nearest enclosing `for_statement`, if any.
fn enclosing_loop_start(node: Node) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "for_statement" {
            return Some(parent.start_byte());
        }
        current = parent;
    }
    None
}

#[derive(Default)]
struct SharedTextInterner<'a> {
    values: HashMap<&'a str, SharedText>,
}

impl<'a> SharedTextInterner<'a> {
    fn intern(&mut self, text: &'a str) -> SharedText {
        if let Some(existing) = self.values.get(text) {
            return Arc::clone(existing);
        }

        let shared: SharedText = Arc::from(text);
        self.values.insert(text, Arc::clone(&shared));
        shared
    }
}

fn extract_argument_texts<'a>(
    args_node: tree_sitter::Node,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) -> Box<[SharedText]> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(interner.intern(text.trim()));
        }
    }
    out.into_boxed_slice()
}

#[doc(hidden)]
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

#[doc(hidden)]
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

//! Fact extraction for Go CWE heuristics.
//!
//! These types are internal to the Go CWE detector bundle. Library consumers
//! see only the `Finding` they produce; the IR lives behind `pub(crate)`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::walk_calls_and_assignments;
use crate::core::ParsedUnit;

use super::source_index::SourceIndex;

type SharedText = Arc<str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    UserControlled,
    TrustedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBinding {
    pub name: SharedText,
    pub kind: InputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: SharedText,
    pub arguments: Box<[SharedText]>,
    pub start_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: SharedText,
    pub expr: SharedText,
    pub start_byte: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GoUnitFacts {
    pub input_bindings: Vec<InputBinding>,
    pub call_facts: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    /// Single-pass substring flags for hot detector guards.
    pub source_index: SourceIndex,
}

pub fn build_go_unit_facts(unit: &ParsedUnit) -> GoUnitFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoUnitFacts::default();
    let mut interner = SharedTextInterner::default();

    walk_calls_and_assignments(root, &mut |node| match node.kind() {
        "call_expression" | "call" => {
            record_call_fact(node, &mut facts, src, &mut interner);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment_fact(node, &mut facts, src, &mut interner);
        }
        _ => {}
    });

    facts.source_index = SourceIndex::build(unit.source.as_ref());
    facts
}

#[derive(Default)]
pub(crate) struct SharedTextInterner<'a> {
    pub(crate) values: HashMap<&'a str, SharedText>,
}

impl<'a> SharedTextInterner<'a> {
    pub(crate) fn intern(&mut self, text: &'a str) -> SharedText {
        if let Some(existing) = self.values.get(text) {
            return Arc::clone(existing);
        }

        let shared: SharedText = Arc::from(text);
        self.values.insert(text, Arc::clone(&shared));
        shared
    }
}

pub(crate) fn extract_argument_texts<'a>(
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

pub(crate) fn record_call_fact<'a>(
    node: tree_sitter::Node,
    facts: &mut GoUnitFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(callee) = func.utf8_text(src) else {
        return;
    };

    let arguments = node
        .child_by_field_name("arguments")
        .map(|args| extract_argument_texts(args, src, interner))
        .unwrap_or_default();

    facts.call_facts.push(CallFact {
        callee: interner.intern(callee),
        arguments,
        start_byte: node.start_byte(),
    });
}

pub(crate) fn record_assignment_fact<'a>(
    node: tree_sitter::Node,
    facts: &mut GoUnitFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Ok(text) = node.utf8_text(src) else {
        return;
    };
    let Some((lhs, rhs)) = split_assignment(text) else {
        return;
    };
    let names = extract_identifiers(lhs);
    if names.is_empty() {
        return;
    }
    let kind = if is_user_input_expr(rhs) {
        Some(InputKind::UserControlled)
    } else if is_trusted_config_expr(rhs) {
        Some(InputKind::TrustedConfig)
    } else {
        None
    };
    if let Some(kind) = kind {
        for name in &names {
            facts.input_bindings.push(InputBinding {
                name: interner.intern(name),
                kind,
            });
        }
    }

    for name in names {
        facts.assignments.push(AssignmentFact {
            name: interner.intern(name),
            expr: interner.intern(rhs),
            start_byte: node.start_byte(),
        });
    }
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

#[doc(hidden)]
pub fn is_user_input_expr(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
        || expr.contains(".GetHeader(")
        || expr.contains(".Header.Get(")
        || expr.contains(".GetRawData(")
        || expr.contains("io.ReadAll(r.Body)")
}

#[doc(hidden)]
pub fn is_trusted_config_expr(expr: &str) -> bool {
    expr.contains("os.Getenv(") || expr.contains("os.LookupEnv(")
}

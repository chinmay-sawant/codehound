//! Fact extraction for Go CWE heuristics.

use crate::ast::{walk_assignments, walk_calls};
use crate::core::ParsedUnit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    UserControlled,
    TrustedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBinding {
    pub name: String,
    pub kind: InputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: String,
    pub arguments: Vec<String>,
    pub start_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: String,
    pub expr: String,
    pub start_byte: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GoUnitFacts {
    pub input_bindings: Vec<InputBinding>,
    pub call_facts: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
}

pub fn build_go_unit_facts(unit: &ParsedUnit) -> GoUnitFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoUnitFacts::default();

    walk_assignments(root, &mut |node| {
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
                    name: (*name).to_string(),
                    kind,
                });
            }
        }

        for name in names {
            facts.assignments.push(AssignmentFact {
                name: name.to_string(),
                expr: rhs.to_string(),
                start_byte: node.start_byte(),
            });
        }
    });

    walk_calls(root, &mut |node| {
        let Some(func) = node.child_by_field_name("function") else {
            return;
        };
        let Ok(callee) = func.utf8_text(src) else {
            return;
        };

        let arguments = node
            .child_by_field_name("arguments")
            .map(|args| extract_argument_texts(args, src))
            .unwrap_or_default();

        facts.call_facts.push(CallFact {
            callee: callee.to_string(),
            arguments,
            start_byte: node.start_byte(),
        });
    });

    facts
}

fn extract_argument_texts(args_node: tree_sitter::Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(text.trim().to_string());
        }
    }
    out
}

fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

fn is_user_input_expr(expr: &str) -> bool {
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

fn is_trusted_config_expr(expr: &str) -> bool {
    expr.contains("os.Getenv(") || expr.contains("os.LookupEnv(")
}

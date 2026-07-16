//! Batch E — testing isolation and functional-option API hygiene.
//!
//! These rules intentionally stay within one parsed Go file. They report only
//! direct writes whose package-level target and enclosing test/option function
//! are visible in the same AST; package-wide lifecycle inference belongs in a
//! separate analysis pass.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-162: a parallel test writes package-level mutable state.
pub(crate) fn detect_bp_162_parallel_test_shared_mutation(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }

    let source = unit.source.as_bytes();
    let globals = package_global_names(unit.tree.root_node(), source);
    if globals.is_empty() {
        return;
    }

    walk_nodes(unit.tree.root_node(), &mut |node| {
        if node.kind() != "function_declaration" || !is_test_function(node, source) {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if !contains_call(body, source, "t.Parallel") {
            return;
        }

        walk_nodes(body, &mut |statement| {
            if !matches!(statement.kind(), "assignment_statement" | "inc_statement") {
                return;
            }
            if !writes_global(statement, source, &globals) {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_162_META,
                statement.start_byte(),
                "parallel test mutates package-level state; use an isolated per-test fixture",
            );
        });
    });
}

/// BP-164: an exported functional option mutates a package-level default.
pub(crate) fn detect_bp_164_option_mutates_global_default(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }

    let source = unit.source.as_bytes();
    let globals = package_global_names(unit.tree.root_node(), source);
    if globals.is_empty() {
        return;
    }

    walk_nodes(unit.tree.root_node(), &mut |node| {
        if node.kind() != "function_declaration" || !is_functional_option(node, source) {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };

        walk_nodes(body, &mut |statement| {
            if statement.kind() != "assignment_statement"
                || !writes_global(statement, source, &globals)
            {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_164_META,
                statement.start_byte(),
                "functional option mutates a package-level default; apply options to the instance instead",
            );
        });
    });
}

fn package_global_names(root: Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        if node.kind() != "var_declaration" {
            continue;
        }
        collect_var_spec_names(node, source, &mut names);
    }
    names
}

fn collect_var_spec_names(node: Node, source: &[u8], names: &mut Vec<String>) {
    if node.kind() == "var_spec" {
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let left = text.split_once('=').map_or(text, |(left, _)| left).trim();
        for name in left.split(',').map(str::trim) {
            if let Some(name) = name.split_whitespace().next()
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                names.push(name.to_owned());
            }
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_var_spec_names(child, source, names);
    }
}

fn is_test_function(node: Node, source: &[u8]) -> bool {
    let Some(name) = node
        .child_by_field_name("name")
        .and_then(|name| name.utf8_text(source).ok())
    else {
        return false;
    };
    (name.starts_with("Test") || name.starts_with("Benchmark") || name.starts_with("Fuzz"))
        && name != "TestMain"
}

fn is_functional_option(node: Node, source: &[u8]) -> bool {
    let Some(name) = node
        .child_by_field_name("name")
        .and_then(|name| name.utf8_text(source).ok())
    else {
        return false;
    };
    if !name.starts_with("With") {
        return false;
    }
    node.child_by_field_name("result")
        .and_then(|result| result.utf8_text(source).ok())
        .is_some_and(|result| result.contains("Option"))
}

fn writes_global(node: Node, source: &[u8], globals: &[String]) -> bool {
    let text = node.utf8_text(source).ok().unwrap_or_default();
    let lhs = if node.kind() == "inc_statement" {
        text.trim().trim_end_matches(['+', '-'])
    } else {
        text.split_once('=').map_or("", |(lhs, _)| lhs.trim())
    };

    lhs.split(',').any(|target| {
        let target = target.trim().trim_start_matches('*').trim();
        globals.iter().any(|global| {
            target == global
                || target.starts_with(&format!("{global}."))
                || target.starts_with(&format!("{global}["))
        })
    })
}

fn contains_call(node: Node, source: &[u8], wanted: &str) -> bool {
    let mut found = false;
    walk_nodes(node, &mut |child| {
        if found || child.kind() != "call_expression" {
            return;
        }
        if child
            .child_by_field_name("function")
            .and_then(|function| function.utf8_text(source).ok())
            == Some(wanted)
        {
            found = true;
        }
    });
    found
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
    }
}

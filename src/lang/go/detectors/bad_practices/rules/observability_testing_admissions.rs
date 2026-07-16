//! Phase 4 — narrow observability/configuration and test-lifecycle checks.
//!
//! This module intentionally admits only patterns that are both high-signal
//! and visible in one Go file. It does not try to infer deployment intent,
//! whole-package constructor contracts, or general error-handling policy.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-161: a test opens a literal DSN that names a production target.
///
/// Environment-provided DSNs and local/container targets are intentionally
/// ignored. The detector requires both a test file and a literal production
/// marker in an `sql.Open` or `gorm.Open` call, so ordinary production-looking
/// variable names cannot trigger it.
pub(crate) fn detect_bp_161_test_uses_production_dsn(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }

    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    let has_sql = has_import(root, source, "database/sql");
    let has_gorm = has_import(root, source, "gorm.io/gorm");
    if !has_sql && !has_gorm {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        if (name == "sql.Open" && !has_sql) || (name == "gorm.Open" && !has_gorm) {
            return;
        }
        if !matches!(name, "sql.Open" | "gorm.Open") {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        if !contains_literal_production_marker(text) {
            return;
        }

        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_161_META,
            node.start_byte(),
            "test opens a literal production DSN; use a local/container target or an explicit test DSN",
        );
    });
}

/// BP-163: a golden-file update path writes without a short-test guard.
///
/// The rule requires a real `flag.Bool`/`flag.BoolVar` update declaration and
/// an `os.WriteFile`/`os.Create` call inside an update branch. This avoids
/// treating arbitrary file writes in tests as snapshot updates.
pub(crate) fn detect_bp_163_unguarded_golden_update(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }

    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    if !has_import(root, source, "flag") || !has_update_flag_declaration(root, source) {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "function_declaration" || !is_test_function(node, source) {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        if contains_call(body, source, "testing.Short") {
            return;
        }

        walk_nodes(body, &mut |candidate| {
            if candidate.kind() != "if_statement" || !is_update_condition(candidate, source) {
                return;
            }
            let Some(consequence) = candidate.child_by_field_name("consequence") else {
                return;
            };
            let Some(write) = find_golden_write(consequence, source) else {
                return;
            };
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_163_META,
                write,
                "golden-file update path writes without a testing.Short() guard",
            );
        });
    });
}

fn has_update_flag_declaration(root: Node, source: &[u8]) -> bool {
    let mut found = false;
    walk_nodes(root, &mut |node| {
        if found
            || !matches!(
                node.kind(),
                "var_declaration" | "short_var_declaration" | "assignment_statement"
            )
        {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        found = text.contains("flag.Bool(\"update\"")
            || text.contains("flag.Bool(\"update-golden\"")
            || text.contains("flag.BoolVar(") && text.contains("\"update\"");
    });
    found
}

fn is_update_condition(node: Node, source: &[u8]) -> bool {
    node.child_by_field_name("condition")
        .and_then(|condition| condition.utf8_text(source).ok())
        .is_some_and(|condition| {
            let normalized = condition.replace(['*', ' ', '\t', '\n'], "");
            normalized == "update"
                || normalized == "updateGolden"
                || normalized.contains("update&&")
        })
}

fn find_golden_write(root: Node, source: &[u8]) -> Option<usize> {
    let mut found = None;
    walk_nodes(root, &mut |node| {
        if found.is_some() || node.kind() != "call_expression" {
            return;
        }
        if matches!(
            call_name(node, source),
            Some("os.WriteFile" | "ioutil.WriteFile" | "os.Create")
        ) {
            found = Some(node.start_byte());
        }
    });
    found
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

fn contains_literal_production_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for (index, _) in lower.match_indices("prod") {
        let before = lower[..index].chars().next_back();
        let after = lower[index + 4..].chars().next();
        let before_ok = before.is_none_or(|character| !character.is_ascii_alphanumeric());
        let after_ok = after.is_none_or(|character| !character.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    for (index, _) in lower.match_indices("production") {
        let before = lower[..index].chars().next_back();
        let after = lower[index + 10..].chars().next();
        let before_ok = before.is_none_or(|character| !character.is_ascii_alphanumeric());
        let after_ok = after.is_none_or(|character| !character.is_ascii_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    let needle = format!("\"{path}\"");
    let mut found = false;
    walk_nodes(root, &mut |node| {
        if !found
            && matches!(node.kind(), "import_spec" | "import_declaration")
            && node
                .utf8_text(source)
                .is_ok_and(|text| text.contains(&needle))
        {
            found = true;
        }
    });
    found
}

fn contains_call(node: Node, source: &[u8], wanted: &str) -> bool {
    let mut found = false;
    walk_nodes(node, &mut |child| {
        if found || child.kind() != "call_expression" {
            return;
        }
        if call_name(child, source) == Some(wanted) {
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

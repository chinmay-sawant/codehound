//! Same-function data-persistence checks for locally owned transactions.
//!
//! BP-126 intentionally does not follow transaction values through helpers or
//! callers. A transaction is reported only when this function can see its
//! `database/sql` acquisition and no local commit/rollback or ownership
//! transfer.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-126: a locally acquired database/sql transaction has no visible finish.
pub(crate) fn detect_bp_126_transaction_without_commit_rollback(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let sql_aliases = sql_import_aliases(root, source);
    if sql_aliases.is_empty() {
        return;
    }

    walk_functions(root, &mut |function| {
        let db_names = database_handle_names(function, source, &sql_aliases);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };

        let mut transactions = Vec::new();
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression" || !is_transaction_begin(node, source, &db_names) {
                return;
            }
            let Some(transaction) = assigned_name(node, source) else {
                return;
            };
            transactions.push((transaction, node.start_byte()));
        });

        for (transaction, begin_byte) in transactions {
            if has_local_finish(body, source, &transaction)
                || is_transferred_locally(body, source, &transaction)
            {
                continue;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_126_META,
                begin_byte,
                "finish the locally acquired transaction with Commit or Rollback, or transfer ownership explicitly",
            );
        }
    });
}

fn is_transaction_begin(call: Node, source: &[u8], db_names: &[String]) -> bool {
    let Some(function) = call_function_text(call, source) else {
        return false;
    };
    let Some((receiver, method)) = function.rsplit_once('.') else {
        return false;
    };
    db_names.iter().any(|name| receiver == name) && matches!(method, "Begin" | "BeginTx")
}

fn has_local_finish(body: Node, source: &[u8], transaction: &str) -> bool {
    let mut finished = false;
    walk_scope(body, body, &mut |node| {
        if finished || node.kind() != "call_expression" {
            return;
        }
        let Some(function) = call_function_text(node, source) else {
            return;
        };
        let Some((receiver, method)) = function.rsplit_once('.') else {
            return;
        };
        if receiver == transaction && matches!(method, "Commit" | "Rollback") {
            finished = true;
        }
    });
    finished
}

/// A direct helper argument or return is an ownership boundary. The caller or
/// helper may be responsible for finishing the transaction; this detector has
/// no interprocedural ownership model and must not report it.
fn is_transferred_locally(body: Node, source: &[u8], transaction: &str) -> bool {
    let mut transferred = false;
    walk_scope(body, body, &mut |node| {
        if transferred {
            return;
        }
        if node.kind() == "return_statement" {
            let returned = node
                .utf8_text(source)
                .unwrap_or_default()
                .trim()
                .strip_prefix("return")
                .unwrap_or_default()
                .trim();
            let first_result = returned.split(',').next().unwrap_or_default().trim();
            if first_result == transaction || first_result == format!("&{transaction}") {
                transferred = true;
            }
            return;
        }
        if node.kind() != "call_expression" {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            let text = argument.utf8_text(source).unwrap_or_default().trim();
            if text == transaction || text == format!("&{transaction}") {
                transferred = true;
                break;
            }
        }
    });
    transferred
}

fn database_handle_names(function: Node, source: &[u8], aliases: &[String]) -> Vec<String> {
    let mut names = parameter_names_with_type(function, source, aliases, "DB");
    let Some(body) = function.child_by_field_name("body") else {
        return names;
    };

    walk_scope(body, body, &mut |node| {
        if !matches!(node.kind(), "var_declaration" | "var_spec") {
            return;
        }
        let text = node.utf8_text(source).unwrap_or_default();
        if aliases.iter().any(|alias| {
            text.contains(&format!("*{alias}.DB")) || text.contains(&format!("{alias}.DB"))
        }) && let Some(name) = declaration_name(text)
        {
            names.push(name);
        }
    });

    walk_scope(body, body, &mut |node| {
        if node.kind() != "short_var_declaration" {
            return;
        }
        let text = node.utf8_text(source).unwrap_or_default();
        let Some((left, right)) = text.split_once(":=") else {
            return;
        };
        let right = right.trim();
        if !aliases.iter().any(|alias| {
            right.starts_with(&format!("{alias}.Open("))
                || right.starts_with(&format!("{alias}.OpenDB("))
        }) {
            return;
        }
        if let Some(name) = left
            .split(',')
            .next()
            .map(str::trim)
            .filter(|name| is_identifier(name))
        {
            names.push(name.to_owned());
        }
    });

    names.sort();
    names.dedup();
    names
}

fn parameter_names_with_type(
    function: Node,
    source: &[u8],
    aliases: &[String],
    type_name: &str,
) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        let type_text = type_node.utf8_text(source).unwrap_or_default().trim();
        let wanted = aliases
            .iter()
            .any(|alias| type_text == format!("*{alias}.{type_name}"));
        if !wanted {
            continue;
        }
        let declaration = parameter.utf8_text(source).unwrap_or_default();
        let prefix = declaration
            .trim()
            .strip_suffix(type_text)
            .unwrap_or_default();
        names.extend(
            prefix
                .split(',')
                .map(str::trim)
                .filter(|name| is_identifier(name))
                .map(str::to_owned),
        );
    }
    names
}

fn sql_import_aliases(root: Node, source: &[u8]) -> Vec<String> {
    let mut aliases = Vec::new();
    walk_nodes(root, &mut |node| {
        if node.kind() != "import_spec" {
            return;
        }
        let text = node.utf8_text(source).unwrap_or_default().trim();
        if !text.contains("\"database/sql\"") {
            return;
        }
        let alias = text
            .split_whitespace()
            .find(|part| *part != "\"database/sql\"")
            .map_or("sql", |part| part.trim_matches('"'));
        if is_identifier(alias) {
            aliases.push(alias.to_owned());
        }
    });
    aliases.sort();
    aliases.dedup();
    aliases
}

fn declaration_name(text: &str) -> Option<String> {
    let text = text.trim().trim_start_matches("var ");
    text.split_whitespace()
        .next()
        .filter(|name| is_identifier(name))
        .map(str::to_owned)
}

fn assigned_name(call: Node, source: &[u8]) -> Option<String> {
    let mut parent = call.parent()?;
    while !matches!(
        parent.kind(),
        "short_var_declaration" | "assignment_statement"
    ) {
        parent = parent.parent()?;
    }
    let text = parent.utf8_text(source).ok()?;
    let left = text
        .split_once(":=")
        .or_else(|| text.split_once('='))
        .map(|(left, _)| left.trim())?;
    left.split(',')
        .next()
        .map(str::trim)
        .filter(|name| is_identifier(name))
        .map(str::to_owned)
}

fn call_function_text<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("function")?.utf8_text(source).ok()
}

fn walk_functions(root: Node, visit: &mut impl FnMut(Node)) {
    if matches!(root.kind(), "function_declaration" | "method_declaration") {
        visit(root);
        return;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_functions(child, visit);
    }
}

fn walk_scope(root: Node, scope: Node, visit: &mut impl FnMut(Node)) {
    if root.id() != scope.id()
        && matches!(
            root.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    {
        return;
    }
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_scope(child, scope, visit);
    }
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

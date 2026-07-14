//! Next data-persistence batch: narrowly gated GORM and sqlx checks.
//!
//! These detectors intentionally use only same-function AST/source facts. They
//! require explicit package imports, typed database parameters, and exact call
//! shapes so generic method names and unknown ownership are left alone.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-136: schema migration must not run from a request handler.
///
/// The handler gate is deliberately conservative: a function must accept a
/// typed GORM database parameter and either standard net/http parameters or a
/// recognized web-framework context parameter. Methods reached through a
/// field or helper are not inferred because this module has no type graph.
pub(crate) fn detect_bp_136_gorm_automigrate_in_request_path(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "gorm.io/gorm") {
        return;
    }

    walk_functions(root, source, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*gorm.DB"]);
        if db_names.is_empty() || !has_request_parameter(function, root, source) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };

        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression" {
                return;
            }
            let Some(name) = call_name(node, source) else {
                return;
            };
            let Some((receiver, method)) = name.rsplit_once('.') else {
                return;
            };
            if method != "AutoMigrate" || !db_names.iter().any(|db| db == receiver.trim()) {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_136_META,
                node.start_byte(),
                "run GORM AutoMigrate at startup or from a separate migration command, not in a request handler",
            );
        });
    });
}

/// BP-142: sqlx.In expands placeholders but does not choose a driver-specific
/// placeholder syntax. The expanded query must be rebound before execution.
///
/// Only a typed *sqlx.DB/*sqlx.Tx parameter and a same-function query flow are
/// accepted. A visible Rebind between sqlx.In and the execution call suppresses
/// the finding; dynamic aliases and helper calls remain out of scope.
pub(crate) fn detect_bp_142_sqlx_in_without_rebind(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/jmoiron/sqlx") {
        return;
    }

    walk_functions(root, source, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*sqlx.DB", "*sqlx.Tx"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };

        let mut in_calls = Vec::new();
        walk_scope(body, body, &mut |node| {
            if node.kind() == "call_expression"
                && call_name(node, source) == Some("sqlx.In")
                && let Some(query_name) = assigned_query_name(node, source)
            {
                in_calls.push((node.start_byte(), node.end_byte(), query_name));
            }
        });

        for (in_call_start, in_call_end, query_name) in in_calls {
            let Some(execution) =
                first_query_execution(body, source, in_call_end, &query_name, &db_names)
            else {
                continue;
            };
            if query_rebound_between(body, source, in_call_end, execution, &query_name, &db_names) {
                continue;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_142_META,
                in_call_start,
                "rebind the query returned by sqlx.In before executing it with the database driver",
            );
        }
    });
}

fn walk_functions(root: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if matches!(root.kind(), "function_declaration" | "method_declaration") {
        visit(root);
        return;
    }

    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_functions(child, source, visit);
    }
    let _ = source;
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
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

fn call_name<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("function")?.utf8_text(source).ok()
}

fn parameter_names_with_types(function: Node, source: &[u8], wanted_types: &[&str]) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        let Ok(type_text) = type_node.utf8_text(source) else {
            continue;
        };
        if !wanted_types
            .iter()
            .any(|wanted| type_text.trim() == *wanted)
        {
            continue;
        }
        let Ok(declaration) = parameter.utf8_text(source) else {
            continue;
        };
        let prefix = declaration
            .trim()
            .strip_suffix(type_text.trim())
            .unwrap_or_default()
            .trim();
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

fn has_request_parameter(function: Node, root: Node, source: &[u8]) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            return false;
        };
        let Ok(type_text) = type_node.utf8_text(source) else {
            return false;
        };
        let type_text = type_text.trim();
        match type_text {
            "http.ResponseWriter" | "*http.Request" => has_import(root, source, "net/http"),
            "*gin.Context" => has_import(root, source, "github.com/gin-gonic/gin"),
            "echo.Context" => has_import(root, source, "github.com/labstack/echo"),
            "*fiber.Ctx" => has_import(root, source, "github.com/gofiber/fiber"),
            "*chi.Context" => has_import(root, source, "github.com/go-chi/chi"),
            _ => false,
        }
    })
}

fn assigned_query_name<'a>(call: Node<'a>, source: &'a [u8]) -> Option<String> {
    let mut parent = call.parent();
    while let Some(node) = parent {
        if matches!(
            node.kind(),
            "short_var_declaration" | "var_declaration" | "assignment_statement"
        ) {
            let text = node.utf8_text(source).ok()?.trim();
            let (left, _) = text.split_once(":=").or_else(|| text.split_once('='))?;
            return left
                .split(',')
                .map(str::trim)
                .find(|name| is_identifier(name))
                .map(str::to_owned);
        }
        parent = node.parent();
    }
    None
}

fn first_query_execution<'a>(
    body: Node<'a>,
    source: &'a [u8],
    after: usize,
    query_name: &str,
    db_names: &[String],
) -> Option<usize> {
    let mut result = None;
    walk_scope(body, body, &mut |node| {
        if result.is_some() || node.start_byte() < after || node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        let Some((receiver, method)) = name.rsplit_once('.') else {
            return;
        };
        if !db_names.iter().any(|db| db == receiver.trim())
            || !matches!(
                method,
                "Exec"
                    | "ExecContext"
                    | "Get"
                    | "Select"
                    | "Query"
                    | "QueryContext"
                    | "QueryRowx"
                    | "Queryx"
            )
        {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        if arguments_contain_identifier(arguments, source, query_name) {
            result = Some(node.start_byte());
        }
    });
    result
}

fn query_rebound_between(
    body: Node,
    source: &[u8],
    after: usize,
    before: usize,
    query_name: &str,
    db_names: &[String],
) -> bool {
    let mut rebound = false;
    walk_scope(body, body, &mut |node| {
        if rebound
            || node.start_byte() < after
            || node.end_byte() > before
            || node.kind() != "call_expression"
        {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        let Some((receiver, method)) = name.rsplit_once('.') else {
            return;
        };
        if method != "Rebind" || !db_names.iter().any(|db| db == receiver.trim()) {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        if arguments_contain_identifier(arguments, source, query_name) {
            rebound = true;
        }
    });
    rebound
}

fn arguments_contain_identifier(arguments: Node, source: &[u8], wanted: &str) -> bool {
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|argument| {
        argument
            .utf8_text(source)
            .ok()
            .is_some_and(|text| text.trim().trim_end_matches("...") == wanted)
    })
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

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
}

//! Locally provable data-persistence checks that are not generic error rules.
//!
//! The checks in this module deliberately stop at same-function facts: typed
//! database parameters, explicit package imports, direct call chains, and
//! visible error-handling branches. Transaction ownership, package-wide
//! configuration, SQL construction, and intent-sensitive rules remain outside
//! this module.

use std::collections::HashSet;

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-128: QueryRow.Scan errors are handled without distinguishing no rows.
pub(crate) fn detect_bp_128_query_row_scan_without_no_rows(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "database/sql") {
        return;
    }

    walk_functions(root, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*sql.DB", "*sql.Tx"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut row_names = HashSet::new();

        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !matches!(
                    call_method(node, source),
                    Some("QueryRow" | "QueryRowContext")
                )
                || !call_starts_with_receiver(node, source, &db_names)
            {
                return;
            }
            if let Some(name) = assigned_name(node, source) {
                row_names.insert(name);
            }
        });

        let body_text = body.utf8_text(source).unwrap_or_default();
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression" || call_method(node, source) != Some("Scan") {
                return;
            }
            let direct_query_row = call_function_text(node, source).is_some_and(|text| {
                db_names.iter().any(|db| {
                    text.starts_with(&format!("{db}.QueryRow("))
                        || text.starts_with(&format!("{db}.QueryRowContext("))
                })
            });
            let row_scan =
                call_receiver(node, source).is_some_and(|receiver| row_names.contains(receiver));
            if !direct_query_row && !row_scan {
                return;
            }
            if body_text.contains("ErrNoRows") {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_128_META,
                node.start_byte(),
                "distinguish sql.ErrNoRows from other QueryRow.Scan failures before mapping the error",
            );
        });
    });
}

/// BP-132: an optimistic-lock-shaped UPDATE ignores RowsAffected.
pub(crate) fn detect_bp_132_update_without_rows_affected(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "database/sql") {
        return;
    }

    walk_functions(root, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*sql.DB", "*sql.Tx"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let body_text = body.utf8_text(source).unwrap_or_default();
        if body_text.contains("RowsAffected") {
            return;
        }

        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !matches!(call_method(node, source), Some("Exec" | "ExecContext"))
                || !call_starts_with_receiver(node, source, &db_names)
            {
                return;
            }
            let Some(query) = first_string_argument(node, source) else {
                return;
            };
            let query = query.to_ascii_lowercase();
            if !query.contains("update")
                || !query.contains("where")
                || (!query.contains("version") && !query.contains("where id"))
            {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_132_META,
                node.start_byte(),
                "check RowsAffected for zero rows after an optimistic-lock-shaped UPDATE",
            );
        });
    });
}

/// BP-133: a GORM chain result is used without checking its Error field.
pub(crate) fn detect_bp_133_gorm_chain_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "gorm.io/gorm") {
        return;
    }

    const TERMINAL_METHODS: &[&str] = &[
        "Find", "First", "Take", "Save", "Create", "Delete", "Update", "Updates",
    ];
    walk_functions(root, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*gorm.DB"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !call_starts_with_receiver(node, source, &db_names)
                || !call_method(node, source)
                    .is_some_and(|method| TERMINAL_METHODS.contains(&method))
                || has_direct_error_selector(node, source)
            {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_133_META,
                node.start_byte(),
                "check the GORM chain's Error field before treating the operation as successful",
            );
        });
    });
}

/// BP-134: First/Take error handling does not account for ErrRecordNotFound.
pub(crate) fn detect_bp_134_gorm_first_without_not_found(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "gorm.io/gorm") {
        return;
    }

    walk_functions(root, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*gorm.DB"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let body_text = body.utf8_text(source).unwrap_or_default();
        if body_text.contains("ErrRecordNotFound") {
            return;
        }
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !call_starts_with_receiver(node, source, &db_names)
                || !matches!(call_method(node, source), Some("First" | "Take"))
                || !has_direct_error_selector(node, source)
            {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_134_META,
                node.start_byte(),
                "handle gorm.ErrRecordNotFound separately from other GORM query failures",
            );
        });
    });
}

/// BP-135: a package-level GORM handle is chained directly in a request path.
pub(crate) fn detect_bp_135_gorm_global_without_session(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "gorm.io/gorm") {
        return;
    }
    let globals = package_gorm_globals(root, source);
    if globals.is_empty() {
        return;
    }

    walk_functions(root, &mut |function| {
        if !has_request_parameter(function, root, source) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut reported_starts = HashSet::new();
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression" {
                return;
            }
            let Some(text) = node.utf8_text(source).ok() else {
                return;
            };
            let Some(global) = globals
                .iter()
                .find(|global| text.starts_with(&format!("{global}.")))
            else {
                return;
            };
            if text.contains(".Session(") || text.contains(".WithContext(") {
                return;
            }
            if !is_gorm_chain_call(text, global) {
                return;
            }
            if !reported_starts.insert(node.start_byte()) {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_135_META,
                node.start_byte(),
                "start the request-scoped GORM chain with WithContext or Session instead of the package-global handle",
            );
        });
    });
}

/// BP-140: a direct sqlx retrieval call is used as a bare expression.
pub(crate) fn detect_bp_140_sqlx_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/jmoiron/sqlx") {
        return;
    }

    const DB_METHODS: &[&str] = &["Get", "GetContext", "Select", "SelectContext"];
    const ROW_METHODS: &[&str] = &["Queryx", "QueryxContext", "QueryRowx", "QueryRowxContext"];
    walk_functions(root, &mut |function| {
        let db_names = parameter_names_with_types(function, source, &["*sqlx.DB", "*sqlx.Tx"]);
        if db_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut row_names = HashSet::new();
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !call_method(node, source).is_some_and(|method| ROW_METHODS.contains(&method))
                || !call_starts_with_receiver(node, source, &db_names)
            {
                return;
            }
            if let Some(name) = assigned_name(node, source) {
                row_names.insert(name);
            }
        });

        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !is_expression_statement(node)
                || !call_method(node, source)
                    .is_some_and(|method| DB_METHODS.contains(&method) || method == "StructScan")
            {
                return;
            }
            let direct_db_call = call_starts_with_receiver(node, source, &db_names);
            let row_scan = call_method(node, source) == Some("StructScan")
                && call_receiver(node, source).is_some_and(|receiver| row_names.contains(receiver));
            if !direct_db_call && !row_scan {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_140_META,
                node.start_byte(),
                "check the sqlx retrieval or StructScan error instead of discarding it as a bare call",
            );
        });
    });
}

/// BP-143: a go-redis command Result is invoked as a bare expression.
pub(crate) fn detect_bp_143_redis_result_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains("redis") {
        return;
    }
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_any_import(
        root,
        source,
        &[
            "github.com/redis/go-redis/v9",
            "github.com/go-redis/redis/v8",
        ],
    ) {
        return;
    }

    const COMMANDS: &[&str] = &["Get", "Set", "Del", "HGet", "HSet", "Do", "Publish", "Incr"];
    walk_functions(root, &mut |function| {
        let redis_names = parameter_names_with_types(
            function,
            source,
            &[
                "*redis.Client",
                "*redis.ClusterClient",
                "redis.UniversalClient",
            ],
        );
        if redis_names.is_empty() {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression"
                || !is_expression_statement(node)
                || call_method(node, source) != Some("Result")
            {
                return;
            }
            let Some(function_text) = call_function_text(node, source) else {
                return;
            };
            let Some(redis_name) = redis_names
                .iter()
                .find(|name| function_text.starts_with(&format!("{name}.")))
            else {
                return;
            };
            let command = function_text
                .strip_prefix(&format!("{redis_name}."))
                .and_then(|text| text.split('(').next())
                .unwrap_or_default();
            if !COMMANDS.contains(&command) {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_143_META,
                node.start_byte(),
                "handle the go-redis command error returned by Result instead of discarding it",
            );
        });
    });
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

fn call_function_text<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("function")?.utf8_text(source).ok()
}

fn call_method<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call_function_text(call, source)?
        .rsplit_once('.')
        .map_or_else(
            || call_function_text(call, source),
            |(_, method)| Some(method),
        )
}

fn call_receiver<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let function = call_function_text(call, source)?;
    let (receiver, _) = function.rsplit_once('.')?;
    is_identifier(receiver).then_some(receiver)
}

fn call_starts_with_receiver(call: Node, source: &[u8], receivers: &[String]) -> bool {
    let Some(function) = call_function_text(call, source) else {
        return false;
    };
    receivers
        .iter()
        .any(|receiver| function.starts_with(&format!("{receiver}.")))
}

fn first_string_argument(call: Node, source: &[u8]) -> Option<String> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).find_map(|argument| {
        let text = argument.utf8_text(source).ok()?.trim();
        is_string_literal(text).then(|| text.to_owned())
    })
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
    let name = left.split(',').next()?.trim();
    is_identifier(name).then_some(name.to_owned())
}

fn has_direct_error_selector(call: Node, source: &[u8]) -> bool {
    let Some(rest) = source.get(call.end_byte()..) else {
        return false;
    };
    std::str::from_utf8(rest)
        .ok()
        .is_some_and(|rest| rest.trim_start().starts_with(".Error"))
}

fn is_expression_statement(call: Node) -> bool {
    call.parent()
        .is_some_and(|parent| parent.kind() == "expression_statement")
}

fn package_gorm_globals(root: Node, source: &[u8]) -> Vec<String> {
    let mut globals = Vec::new();
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        if node.kind() != "var_declaration" {
            continue;
        }
        let Ok(text) = node.utf8_text(source) else {
            continue;
        };
        for declaration in text.lines() {
            let declaration = declaration.trim();
            let rest = declaration.strip_prefix("var ").unwrap_or(declaration);
            let Some(name) = rest.split_whitespace().next() else {
                continue;
            };
            if name != "(" && declaration.contains("*gorm.DB") && is_identifier(name) {
                globals.push(name.to_owned());
            }
        }
    }
    globals
}

fn is_gorm_chain_call(text: &str, global: &str) -> bool {
    const CHAIN_METHODS: &[&str] = &[
        "Where(", "Model(", "Select(", "Order(", "Joins(", "Preload(", "Scopes(", "Find(",
        "First(", "Take(", "Save(", "Create(", "Delete(", "Update(", "Updates(",
    ];
    let Some(chain) = text.strip_prefix(&format!("{global}.")) else {
        return false;
    };
    CHAIN_METHODS.iter().any(|method| chain.contains(method))
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
        match type_text.trim() {
            "http.ResponseWriter" | "*http.Request" => has_import(root, source, "net/http"),
            "*gin.Context" => has_import(root, source, "github.com/gin-gonic/gin"),
            "echo.Context" => has_import(root, source, "github.com/labstack/echo"),
            "*fiber.Ctx" => has_import(root, source, "github.com/gofiber/fiber"),
            _ => false,
        }
    })
}

fn parameter_names_with_types(function: Node, source: &[u8], wanted: &[&str]) -> Vec<String> {
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
        if !wanted.iter().any(|wanted| type_text.trim() == *wanted) {
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

fn has_any_import(root: Node, source: &[u8], paths: &[&str]) -> bool {
    paths.iter().any(|path| has_import(root, source, path))
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

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
    }
}

fn is_string_literal(value: &str) -> bool {
    (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('`') && value.ends_with('`'))
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

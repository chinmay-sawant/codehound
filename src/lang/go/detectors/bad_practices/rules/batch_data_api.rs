//! Batch D — conservative data, observability, and API lifecycle checks.
//!
//! These rules deliberately stay within one parsed Go file. They require an
//! explicit package import and use source/AST facts that do not need go/types,
//! SSA, or runtime configuration. Registration, metadata, and fixture-manifest
//! changes belong to the central integration pass.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-131: use Exec/ExecContext for a literal DML statement instead of Query.
///
/// A literal statement containing RETURNING is excluded because Query is the
/// intended API when rows are deliberately returned by the database.
pub(crate) fn detect_bp_131_query_for_exec_only(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !has_import(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        "database/sql",
    ) {
        return;
    }

    walk_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let sql_receivers =
                parameter_names_with_types(function, source, &["*sql.DB", "*sql.Tx"]);
            walk_calls(body, source, &mut |call| {
                let Some(name) = call_name(call, source) else {
                    return;
                };
                if !matches!(name, n if n.ends_with(".Query") || n.ends_with(".QueryContext")) {
                    return;
                }
                let Some(receiver) = receiver_name(name) else {
                    return;
                };
                if !sql_receivers.iter().any(|candidate| candidate == receiver) {
                    return;
                }
                let Some(sql) = sql_literal_argument(call, source) else {
                    return;
                };
                if !is_exec_only_sql_literal(sql) {
                    return;
                }

                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_131_META,
                    call.start_byte(),
                    "use Exec/ExecContext for a DML statement that does not return rows",
                );
            });
        },
    );
}

/// BP-145: a pgx pool connection is acquired but never returned to the pool.
pub(crate) fn detect_bp_145_pool_conn_not_released(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    if !has_any_import(
        unit.tree.root_node(),
        source,
        &[
            "github.com/jackc/pgx/v4/pgxpool",
            "github.com/jackc/pgx/v5/pgxpool",
        ],
    ) {
        return;
    }

    walk_functions(unit.tree.root_node(), source, |function, source| {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let Some(body_text) = body.utf8_text(source).ok() else {
            return;
        };
        let pool_receivers = parameter_names_with_types(function, source, &["*pgxpool.Pool"]);
        walk_nodes(body, &mut |node| {
            if !matches!(node.kind(), "short_var_declaration" | "var_declaration") {
                return;
            }
            let Some(text) = node.utf8_text(source).ok() else {
                return;
            };
            let Some((left, right)) = assignment_parts(text) else {
                return;
            };
            if !right.contains(".Acquire(") {
                return;
            }
            let Some(acquire_receiver) = right
                .split_once(".Acquire(")
                .map(|(receiver, _)| receiver.trim().rsplit('.').next().unwrap_or(receiver))
            else {
                return;
            };
            if !pool_receivers
                .iter()
                .any(|candidate| candidate == acquire_receiver)
            {
                return;
            }
            let Some(connection) = first_identifier(left) else {
                return;
            };
            if connection == "_" {
                return;
            }
            let acquire_offset = right.find(".Acquire(").unwrap_or(0);
            let release_markers = [
                format!("{connection}.Release("),
                format!("{connection}.Close("),
            ];
            let statement_end = node.end_byte().saturating_sub(body.start_byte());
            let released_later = release_markers.iter().any(|marker| {
                body_text
                    .get(statement_end..)
                    .is_some_and(|tail| tail.contains(marker))
            });
            if released_later {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_145_META,
                node.start_byte() + text.find(".Acquire").unwrap_or(acquire_offset),
                "pgx pool connection is acquired without a visible Release or Close",
            );
        });
    });
}

/// BP-159: a flag pointer is dereferenced before the package parses flags.
pub(crate) fn detect_bp_159_flag_used_before_parse(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    if !has_import(unit.tree.root_node(), source, "flag") {
        return;
    }

    walk_functions(unit.tree.root_node(), source, |function, source| {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let Some(parse_start) = find_call_start(body, source, "flag.Parse") else {
            return;
        };
        let flag_names = flag_pointer_names(body, source);
        if flag_names.is_empty() {
            return;
        }

        walk_nodes(body, &mut |node| {
            if node.kind() != "unary_expression" || node.start_byte() >= parse_start {
                return;
            }
            let Some(text) = node.utf8_text(source).ok() else {
                return;
            };
            let name = text.trim().strip_prefix('*').map(str::trim);
            if !name.is_some_and(|name| flag_names.iter().any(|candidate| candidate == name)) {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_159_META,
                node.start_byte(),
                "flag value is read before flag.Parse() processes command-line arguments",
            );
        });
    });
}

fn is_exec_only_sql_literal(argument: &str) -> bool {
    let sql = argument.trim();
    let Some(sql) = sql
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            sql.strip_prefix('`')
                .and_then(|value| value.strip_suffix('`'))
        })
    else {
        return false;
    };
    let normalized = sql.trim().to_ascii_uppercase();
    ["INSERT ", "UPDATE ", "DELETE "]
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
        && !normalized.contains(" RETURNING ")
}

fn flag_pointer_names(body: Node, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    walk_nodes(body, &mut |node| {
        if !matches!(node.kind(), "short_var_declaration" | "var_declaration") {
            return;
        }
        let Some(text) = node.utf8_text(source).ok() else {
            return;
        };
        let Some((left, right)) = assignment_parts(text) else {
            return;
        };
        let constructors = [
            "flag.Bool(",
            "flag.Duration(",
            "flag.Float64(",
            "flag.Int(",
            "flag.Int64(",
            "flag.String(",
            "flag.Uint(",
            "flag.Uint64(",
        ];
        if constructors
            .iter()
            .any(|constructor| right.contains(constructor))
            && let Some(name) = first_identifier(left)
        {
            names.push(name.to_owned());
        }
    });
    names
}

fn assignment_parts(text: &str) -> Option<(&str, &str)> {
    text.split_once(":=").or_else(|| text.split_once('='))
}

fn first_identifier(text: &str) -> Option<&str> {
    text.trim()
        .strip_prefix("var ")
        .unwrap_or(text.trim())
        .split(',')
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn receiver_name(call_name: &str) -> Option<&str> {
    call_name
        .rsplit_once('.')
        .map(|(receiver, _)| receiver.trim())
}

fn parameter_names_with_types(function: Node, source: &[u8], type_markers: &[&str]) -> Vec<String> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let Ok(text) = parameters.utf8_text(source) else {
        return Vec::new();
    };
    text.trim_matches(&['(', ')'][..])
        .split(',')
        .filter_map(|parameter| {
            if !type_markers.iter().any(|marker| parameter.contains(marker)) {
                return None;
            }
            parameter.split_whitespace().next().map(str::to_owned)
        })
        .collect()
}

fn sql_literal_argument<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).find_map(|argument| {
        let text = argument.utf8_text(source).ok()?.trim();
        (text.starts_with('"') || text.starts_with('`')).then_some(text)
    })
}

fn call_name<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("function")?.utf8_text(source).ok()
}

fn find_call_start(body: Node, source: &[u8], wanted: &str) -> Option<usize> {
    let mut result = None;
    walk_nodes(body, &mut |node| {
        if result.is_none()
            && node.kind() == "call_expression"
            && call_name(node, source) == Some(wanted)
        {
            result = Some(node.start_byte());
        }
    });
    result
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

fn walk_functions(root: Node, source: &[u8], mut visit: impl FnMut(Node, &[u8])) {
    walk_nodes(root, &mut |node| {
        if matches!(node.kind(), "function_declaration" | "method_declaration") {
            visit(node, source);
        }
    });
}

fn walk_calls(body: Node, _source: &[u8], visit: &mut impl FnMut(Node)) {
    walk_nodes(body, &mut |node| {
        if node.kind() == "call_expression" {
            visit(node);
        }
    });
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    fn walk(node: Node, visit: &mut impl FnMut(Node)) {
        visit(node);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, visit);
        }
    }
    walk(root, visit);
}

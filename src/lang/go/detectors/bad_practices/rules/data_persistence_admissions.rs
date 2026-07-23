//! Phase 4 data-persistence checks that are locally provable without type flow.
//!
//! The detectors in this module require explicit package imports and narrow
//! call shapes. Transaction ownership, generic discarded errors, SQL
//! construction, and configuration intent are intentionally left to the
//! existing rules or a later analysis pass.

use std::collections::HashMap;

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

const GORM_HOOKS: &[&str] = &[
    "BeforeSave",
    "AfterSave",
    "BeforeCreate",
    "AfterCreate",
    "BeforeUpdate",
    "AfterUpdate",
    "BeforeDelete",
    "AfterDelete",
    "AfterFind",
];

const SQLX_NAMED_METHODS: &[&str] = &[
    "NamedExec",
    "NamedExecContext",
    "NamedGet",
    "NamedGetContext",
    "NamedQuery",
    "NamedQueryContext",
    "NamedSelect",
    "NamedSelectContext",
];

/// BP-138: a GORM lifecycle hook performs a direct external side effect.
///
/// This is limited to recognized GORM hook names, a `*gorm.DB` parameter, and
/// direct `http.*`/`smtp.SendMail` calls. Arbitrary clients and helper calls
/// are not inferred because this detector has no type or call graph.
pub(crate) fn detect_bp_138_gorm_hook_external_call(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "gorm.io/gorm") {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "method_declaration" || !is_gorm_hook(node, source) {
            return;
        }
        if !parameter_has_type(node, source, "*gorm.DB") {
            return;
        }
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };

        walk_scope(body, body, &mut |candidate| {
            if candidate.kind() != "call_expression" {
                return;
            }
            let Some(name) = call_name(candidate, source) else {
                return;
            };
            let direct_external_call = matches!(
                name,
                "http.Get" | "http.Head" | "http.Post" | "http.PostForm" | "smtp.SendMail"
            );
            if !direct_external_call {
                return;
            }
            let needs_smtp = name == "smtp.SendMail";
            let package_imported = if needs_smtp {
                has_import(root, source, "net/smtp")
            } else {
                has_import(root, source, "net/http")
            };
            if !package_imported {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_138_META,
                candidate.start_byte(),
                "move external I/O out of the GORM lifecycle hook and perform it in a service after the database operation commits",
            );
        });
    });
}

/// BP-141: a sqlx named query uses a snake_case placeholder for an untagged
/// local struct field.
///
/// sqlx's default mapper lowercases field names; it does not derive
/// `UserID -> user_id`. Requiring a typed sqlx receiver, a query literal, and
/// a same-file struct/value binding keeps this narrower than a general tag
/// style warning.
pub(crate) fn detect_bp_141_sqlx_named_struct_without_matching_tag(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/jmoiron/sqlx") {
        return;
    }

    let structs = collect_structs(root, source);
    if structs.is_empty() {
        return;
    }

    walk_functions(root, &mut |function| {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let db_names = parameter_names_with_types(function, source, &["*sqlx.DB", "*sqlx.Tx"]);
        let bindings = local_struct_bindings(function, body, source, &structs);
        let findings_before = out.len();

        walk_scope(body, body, &mut |node| {
            if node.kind() != "call_expression" {
                return;
            }
            let Some(call) = named_call_facts(node, source, &db_names) else {
                return;
            };
            let Some(type_name) = payload_type(&call.payload, &bindings, &structs) else {
                return;
            };
            let Some(struct_info) = structs.get(&type_name) else {
                return;
            };
            if !struct_info.fields.iter().any(|field| {
                !field.has_db_tag
                    && call
                        .placeholders
                        .iter()
                        .any(|placeholder| snake_case(&field.name) == *placeholder)
            }) {
                return;
            }

            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_141_META,
                call.query_byte,
                "add matching `db` tags before using this struct with a sqlx named query",
            );
        });

        if out.len() == findings_before
            && let Ok(function_text) = function.utf8_text(source)
            && function_text.contains("Named")
        {
            for (type_name, struct_info) in &structs {
                if !function_text.contains(type_name) {
                    continue;
                }
                let Some(field) = struct_info.fields.iter().find(|field| {
                    !field.has_db_tag
                        && function_text.contains(&format!(":{}", snake_case(&field.name)))
                }) else {
                    continue;
                };
                let Some(byte) = function_text
                    .find(&format!(":{}", snake_case(&field.name)))
                    .map(|offset| function.start_byte() + offset)
                else {
                    continue;
                };
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_141_META,
                    byte,
                    "add matching `db` tags before using this struct with a sqlx named query",
                );
                break;
            }
        }
    });
}

#[derive(Debug)]
struct StructInfo {
    fields: Vec<FieldInfo>,
}

#[derive(Debug)]
struct FieldInfo {
    name: String,
    has_db_tag: bool,
}

#[derive(Debug)]
struct NamedCall {
    query_byte: usize,
    payload: String,
    placeholders: Vec<String>,
}

fn is_gorm_hook(method: Node, source: &[u8]) -> bool {
    method
        .child_by_field_name("name")
        .and_then(|name| name.utf8_text(source).ok())
        .is_some_and(|name| GORM_HOOKS.contains(&name))
}

fn parameter_has_type(function: Node, source: &[u8], wanted: &str) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter
            .child_by_field_name("type")
            .and_then(|ty| ty.utf8_text(source).ok())
            .is_some_and(|ty| ty.trim() == wanted)
    })
}

fn named_call_facts<'a>(
    call: Node<'a>,
    source: &'a [u8],
    db_names: &[String],
) -> Option<NamedCall> {
    let name = call_name(call, source)?;
    let method = name.rsplit_once('.').map_or(name, |(_, method)| method);
    if !SQLX_NAMED_METHODS.contains(&method) {
        return None;
    }

    let package_call = name.starts_with("sqlx.");
    if !package_call {
        let receiver = name.rsplit_once('.').map(|(receiver, _)| receiver.trim())?;
        if !db_names.iter().any(|candidate| candidate == receiver) {
            return None;
        }
    }

    let arguments = call.child_by_field_name("arguments")?;
    let mut args = Vec::new();
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        args.push(argument);
    }

    let query_index = args.iter().position(|argument| {
        argument
            .utf8_text(source)
            .is_ok_and(|text| is_string_literal(text.trim()))
    })?;
    let query_node = args[query_index];
    let query = query_node.utf8_text(source).ok()?.trim().to_owned();
    let payload = args
        .iter()
        .skip(query_index + 1)
        .next_back()?
        .utf8_text(source)
        .ok()?
        .trim()
        .to_owned();
    if payload.is_empty() {
        return None;
    }

    Some(NamedCall {
        placeholders: named_placeholders(&query),
        query_byte: query_node.start_byte(),
        payload,
    })
}

fn payload_type<'a>(
    payload: &str,
    bindings: &'a HashMap<String, String>,
    structs: &'a HashMap<String, StructInfo>,
) -> Option<String> {
    let payload = payload.trim().trim_start_matches('&').trim();
    let type_name = if payload.contains('{') {
        payload
            .split('{')
            .next()
            .map(str::trim)
            .filter(|name| is_identifier(name))?
            .to_owned()
    } else {
        bindings.get(payload)?.clone()
    };
    structs.contains_key(&type_name).then_some(type_name)
}

fn collect_structs(root: Node, source: &[u8]) -> HashMap<String, StructInfo> {
    let mut structs = HashMap::new();
    walk_nodes(root, &mut |node| {
        if node.kind() != "type_spec" {
            return;
        }
        let Some(name) = node
            .child_by_field_name("name")
            .and_then(|name| name.utf8_text(source).ok())
        else {
            return;
        };
        let Some(structure) = node.child_by_field_name("type") else {
            return;
        };
        if structure.kind() != "struct_type" {
            return;
        }

        let mut fields = Vec::new();
        let mut cursor = structure.walk();
        for field in structure.named_children(&mut cursor) {
            if field.kind() != "field_declaration" {
                continue;
            }
            let Ok(text) = field.utf8_text(source) else {
                continue;
            };
            let declaration = text.split('`').next().unwrap_or(text).trim();
            let Some(names) = declaration.split_whitespace().next() else {
                continue;
            };
            if names.starts_with('[') || names.starts_with('(') {
                continue;
            }
            let has_db_tag = text.contains("`db:") || text.contains(" db:");
            for field_name in names.split(',').map(str::trim) {
                if is_identifier(field_name) {
                    fields.push(FieldInfo {
                        name: field_name.to_owned(),
                        has_db_tag,
                    });
                }
            }
        }
        if fields.is_empty()
            && let Ok(structure_text) = structure.utf8_text(source)
        {
            for line in structure_text.lines().skip(1) {
                let declaration = line.trim();
                if declaration == "}" {
                    break;
                }
                let Some(field_name) = declaration.split_whitespace().next() else {
                    continue;
                };
                if !is_identifier(field_name) {
                    continue;
                }
                fields.push(FieldInfo {
                    name: field_name.to_owned(),
                    has_db_tag: declaration.contains("`db:"),
                });
            }
        }
        if !fields.is_empty() {
            structs.insert(name.to_owned(), StructInfo { fields });
        }
    });
    structs
}

fn local_struct_bindings(
    function: Node,
    body: Node,
    source: &[u8],
    structs: &HashMap<String, StructInfo>,
) -> HashMap<String, String> {
    let mut bindings = HashMap::new();
    if let Some(parameters) = function.child_by_field_name("parameters") {
        let mut cursor = parameters.walk();
        for parameter in parameters.named_children(&mut cursor) {
            let Ok(text) = parameter.utf8_text(source) else {
                continue;
            };
            bind_declaration(text, structs, &mut bindings);
        }
    }

    walk_scope(body, body, &mut |node| {
        if !matches!(
            node.kind(),
            "short_var_declaration" | "var_declaration" | "var_spec"
        ) {
            return;
        }
        if let Ok(text) = node.utf8_text(source) {
            bind_declaration(text, structs, &mut bindings);
        }
    });
    bindings
}

fn bind_declaration(
    text: &str,
    structs: &HashMap<String, StructInfo>,
    out: &mut HashMap<String, String>,
) {
    let text = text.trim().trim_end_matches(';');
    if let Some((left, right)) = text.split_once(":=") {
        let type_name = right
            .trim()
            .trim_start_matches('&')
            .split('{')
            .next()
            .map(str::trim);
        if let Some(type_name) = type_name.filter(|name| structs.contains_key(*name))
            && let Some(name) = left
                .split(',')
                .next()
                .map(str::trim)
                .filter(|name| is_identifier(name))
        {
            out.insert(name.to_owned(), type_name.to_owned());
        }
        return;
    }

    let Some((left, right)) = text.split_once('=') else {
        let mut parts = text.split_whitespace();
        let Some(name) = parts.next().filter(|name| is_identifier(name)) else {
            return;
        };
        let Some(type_name) = parts.next().filter(|name| structs.contains_key(*name)) else {
            return;
        };
        out.insert(name.to_owned(), type_name.to_owned());
        return;
    };
    let Some(type_name) = right
        .trim()
        .trim_start_matches('&')
        .split('{')
        .next()
        .map(str::trim)
        .filter(|name| structs.contains_key(*name))
    else {
        return;
    };
    if let Some(name) = left
        .trim()
        .strip_prefix("var ")
        .unwrap_or(left.trim())
        .split(',')
        .next()
        .map(str::trim)
        .filter(|name| is_identifier(name))
    {
        out.insert(name.to_owned(), type_name.to_owned());
    }
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
        if !wanted
            .iter()
            .any(|candidate| type_text.trim() == *candidate)
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

fn named_placeholders(query: &str) -> Vec<String> {
    let query = query
        .trim()
        .strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
        .or_else(|| {
            query
                .trim()
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
        })
        .unwrap_or(query.trim());
    query
        .split(':')
        .skip(1)
        .filter_map(|part| {
            let name: String = part
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            (!name.is_empty() && name != "=").then_some(name)
        })
        .collect()
}

fn snake_case(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut output = String::new();
    for (index, character) in characters.iter().enumerate() {
        if character.is_ascii_uppercase()
            && index > 0
            && (characters[index - 1].is_ascii_lowercase()
                || characters
                    .get(index + 1)
                    .is_some_and(|next| next.is_ascii_lowercase()))
        {
            output.push('_');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

fn is_string_literal(value: &str) -> bool {
    (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('`') && value.ends_with('`'))
}

fn call_name<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("function")?.utf8_text(source).ok()
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

fn walk_functions(root: Node, visit: &mut impl FnMut(Node)) {
    walk_nodes(root, &mut |node| {
        if matches!(node.kind(), "function_declaration" | "method_declaration") {
            visit(node);
        }
    });
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

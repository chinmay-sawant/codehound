use std::collections::HashMap;
use std::sync::Arc;

use crate::core::ParsedUnit;

use super::super::{
    CallGraph, CallSite, FunctionDecl, ProjectCallGraph, SharedText, normalize_receiver_type,
};
use super::walker_records::result_variable_of_call;

pub fn extract_call_graph(unit: &ParsedUnit) -> CallGraph {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut cg = CallGraph::default();

    let mut cursor = root.walk();
    walk_call_graph(root, &mut cursor, src, &mut cg);
    cg
}

fn walk_call_graph(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    src: &[u8],
    cg: &mut CallGraph,
) {
    match node.kind() {
        "function_declaration" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Ok(name) = name_node.utf8_text(src) else {
                return;
            };
            let params = node.child_by_field_name("parameters");
            let param_count = params.map_or(0, |p| p.named_child_count());

            cg.add_declaration(
                Arc::from(name),
                FunctionDecl {
                    name: Arc::from(name),
                    param_count,
                    is_method: false,
                    receiver_type: None,
                },
            );
        }
        "method_declaration" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Ok(name) = name_node.utf8_text(src) else {
                return;
            };
            let params = node.child_by_field_name("parameters");
            let param_count = params.map_or(0, |p| p.named_child_count());
            let receiver = node
                .child_by_field_name("receiver")
                .and_then(|r| r.utf8_text(src).ok())
                .map(Arc::from);
            let identity = receiver
                .as_deref()
                .map(normalize_receiver_type)
                .filter(|receiver| !receiver.is_empty())
                .map(|receiver| format!("{receiver}.{name}"))
                .unwrap_or_else(|| name.to_string());

            cg.add_declaration(
                Arc::from(identity),
                FunctionDecl {
                    name: Arc::from(name),
                    param_count,
                    is_method: true,
                    receiver_type: receiver,
                },
            );
        }
        "call_expression" => {
            record_call_site(node, src, cg);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            walk_call_graph(child, cursor, src, cg);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn record_call_site(node: tree_sitter::Node, src: &[u8], cg: &mut CallGraph) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(callee) = func.utf8_text(src) else {
        return;
    };

    let caller_name = enclosing_function(node, src);
    let is_method_call = func.kind() == "selector_expression";

    let args = argument_texts(node, src);
    let byte_range = node.start_byte()..node.end_byte();

    let assignment_lhs = result_variable_of_call(node, src).map(Arc::from);
    let returns_result = call_result_is_returned(node, src, assignment_lhs.as_deref());

    cg.add_site(CallSite {
        caller: caller_name,
        callee: Arc::from(callee),
        byte_range,
        arguments: args,
        assignment_lhs,
        returns_result,
        is_method_call,
        is_closure: callee.starts_with("func(") || callee.starts_with("func "),
    });
}

fn call_result_is_returned(
    node: tree_sitter::Node,
    src: &[u8],
    assignment_lhs: Option<&str>,
) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        match current.kind() {
            "return_statement" => return true,
            "function_declaration" | "method_declaration" | "func_literal" => {
                let Some(lhs) = assignment_lhs else {
                    return false;
                };
                let Some(body) =
                    std::str::from_utf8(&src[current.start_byte()..current.end_byte()]).ok()
                else {
                    return false;
                };
                return lhs.split(',').any(|name| {
                    let name = name.trim();
                    body.lines().any(|line| {
                        let Some(rest) = line.trim_start().strip_prefix("return") else {
                            return false;
                        };
                        let Some(first) = rest
                            .trim_start()
                            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                            .next()
                        else {
                            return false;
                        };
                        first == name
                    })
                });
            }
            _ => parent = current.parent(),
        }
    }
    false
}

fn enclosing_function(node: tree_sitter::Node, src: &[u8]) -> SharedText {
    let mut parent = node.parent();
    while let Some(p) = parent {
        match p.kind() {
            "function_declaration" => {
                if let Some(name) = p
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(src).ok())
                {
                    return Arc::from(name);
                }
            }
            "method_declaration" => {
                if let Some(name) = p
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(src).ok())
                {
                    let receiver = p
                        .child_by_field_name("receiver")
                        .and_then(|r| r.utf8_text(src).ok())
                        .map(normalize_receiver_type)
                        .filter(|receiver| !receiver.is_empty());
                    return match receiver {
                        Some(receiver) => Arc::from(format!("{receiver}.{name}")),
                        None => Arc::from(name),
                    };
                }
            }
            "func_literal" => {
                return Arc::from("<anonymous>");
            }
            _ => {}
        }
        parent = p.parent();
    }
    Arc::from("<top-level>")
}

/// Merge per-file `CallGraph`s into a project-level `ProjectCallGraph`.
pub fn merge_call_graphs<'a>(
    units: impl IntoIterator<Item = (&'a str, &'a CallGraph)>,
) -> ProjectCallGraph {
    let mut calls: HashMap<String, Vec<CallSite>> = HashMap::new();
    let mut declarations: HashMap<String, FunctionDecl> = HashMap::new();
    for (_path, cg) in units {
        for (name, decl) in &cg.declarations {
            declarations.insert(name.to_string(), decl.clone());
        }
        for (caller, indices) in &cg.by_caller {
            let entry = calls.entry(caller.to_string()).or_default();
            for &idx in indices {
                if let Some(site) = cg.sites.get(idx) {
                    entry.push(site.clone());
                }
            }
        }
    }
    ProjectCallGraph {
        calls,
        declarations,
    }
}

fn argument_texts(call: tree_sitter::Node, src: &[u8]) -> Box<[SharedText]> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Box::new([]);
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter_map(|n| n.utf8_text(src).ok())
        .map(Arc::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_file_method_declarations_have_distinct_receiver_qualified_keys() {
        let source = r#"package main
type Safe struct{}
type Sink struct{}
func (s *Safe) Open(value string) { _ = value }
func (s *Sink) Open(value string) { os.Open(value) }
"#;
        let unit = crate::lang::parser::parse_go(source).expect("valid Go");
        let graph = extract_call_graph(&unit);

        assert!(graph.declarations.contains_key("*Safe.Open"));
        assert!(graph.declarations.contains_key("*Sink.Open"));
        assert_eq!(graph.declarations.len(), 2);
    }
}

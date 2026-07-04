use std::collections::HashMap;
use std::sync::Arc;

use crate::core::ParsedUnit;

use super::super::{CallGraph, CallSite, FunctionDecl, ProjectCallGraph, SharedText};

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
            let Some(name_node) = node.child_by_field_name("name") else { return };
            let Ok(name) = name_node.utf8_text(src) else { return };
            let params = node.child_by_field_name("parameters");
            let param_count = params.map_or(0, |p| p.named_child_count());

            cg.declarations.insert(
                Arc::from(name),
                FunctionDecl {
                    param_count,
                    is_method: false,
                    receiver_type: None,
                },
            );
        }
        "method_declaration" => {
            let Some(name_node) = node.child_by_field_name("name") else { return };
            let Ok(name) = name_node.utf8_text(src) else { return };
            let params = node.child_by_field_name("parameters");
            let param_count = params.map_or(0, |p| p.named_child_count());
            let receiver = node
                .child_by_field_name("receiver")
                .and_then(|r| {
                    r.named_children(&mut r.walk())
                        .find_map(|c| c.utf8_text(src).ok())
                })
                .map(Arc::from);

            cg.declarations.insert(
                Arc::from(name),
                FunctionDecl {
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
    let Some(func) = node.child_by_field_name("function") else { return };
    let Ok(callee) = func.utf8_text(src) else { return };

    let caller_name = enclosing_function(node, src);
    let is_method_call = func.kind() == "selector_expression";

    let args = argument_texts(node, src);
    let byte_range = node.start_byte()..node.end_byte();

    cg.add_site(CallSite {
        caller: caller_name,
        callee: Arc::from(callee),
        byte_range,
        arguments: args,
        is_method_call,
        is_closure: callee.starts_with("func(") || callee.starts_with("func "),
    });
}

fn enclosing_function<'a>(node: tree_sitter::Node, src: &'a [u8]) -> SharedText {
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
                    return Arc::from(name);
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
    ProjectCallGraph { calls, declarations }
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

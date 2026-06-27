//! Build a `TaintGraph` from raw annotations.

use std::collections::HashMap;
use std::sync::Arc;

use super::super::{
    EdgeKind, ScopeId, ScopeInfo, SharedText, TaintAnnotations, TaintGraph, TaintNode, TaintNodeId,
};

/// Build a `TaintGraph` from raw annotations.
pub fn build_taint_graph(annotations: &TaintAnnotations) -> TaintGraph {
    let mut graph = TaintGraph::default();

    // Map each assignment to a variable node, keyed by (scope, name).
    // We keep only the *latest* assignment per variable within a scope for
    // the MVP; re-assignments overwrite the previous decl node.
    let mut decl_nodes: HashMap<(ScopeId, SharedText), TaintNodeId> = HashMap::new();

    // Index scopes by id for parent lookups.
    let scope_by_id: HashMap<ScopeId, &ScopeInfo> =
        annotations.scopes.iter().map(|s| (s.id, s)).collect();

    // Create variable nodes for every assignment.
    for assignment in &annotations.assignments {
        let node = TaintNode::Variable {
            name: Arc::clone(&assignment.lhs),
            type_hint: None,
            scope: assignment.scope,
            decl_byte: assignment.byte_range.start,
        };
        let id = graph.add_node(node);
        decl_nodes.insert((assignment.scope, Arc::clone(&assignment.lhs)), id);
    }

    // Add source / sink / sanitizer nodes and wire them to result variables
    // and argument variables.
    for source in &annotations.sources {
        let id = graph.add_node(TaintNode::Source {
            function: Arc::clone(&source.function),
            kind: source.kind,
            byte_range: source.byte_range.clone(),
        });
        if let Some(var) = &source.result_variable {
            if let Some(target) =
                resolve_variable(&decl_nodes, &scope_by_id, source.byte_range.start, var)
            {
                graph.add_edge(id, target, EdgeKind::Assignment);
            }
        }
        wire_arguments(
            &mut graph,
            &decl_nodes,
            &scope_by_id,
            id,
            source.byte_range.start,
            &source.arguments,
        );
    }

    for sanitizer in &annotations.sanitizers {
        let id = graph.add_node(TaintNode::Sanitizer {
            function: Arc::clone(&sanitizer.function),
            kind: sanitizer.kind,
            byte_range: sanitizer.byte_range.clone(),
        });
        if let Some(var) = &sanitizer.result_variable {
            if let Some(target) =
                resolve_variable(&decl_nodes, &scope_by_id, sanitizer.byte_range.start, var)
            {
                graph.add_edge(id, target, EdgeKind::Assignment);
            }
        }
        wire_arguments(
            &mut graph,
            &decl_nodes,
            &scope_by_id,
            id,
            sanitizer.byte_range.start,
            &sanitizer.arguments,
        );
    }

    for sink in &annotations.sinks {
        let id = graph.add_node(TaintNode::Sink {
            function: Arc::clone(&sink.function),
            kind: sink.kind,
            argument_index: sink.argument_index,
            byte_range: sink.byte_range.clone(),
        });
        // Wire any identifier argument to its declaring variable.
        for (idx, arg) in sink.all_arguments.iter().enumerate() {
            if let Some(arg_var) = as_simple_identifier(arg) {
                if let Some(source_id) =
                    resolve_variable(&decl_nodes, &scope_by_id, sink.byte_range.start, arg_var)
                {
                    graph.add_edge(source_id, id, EdgeKind::Argument(idx));
                }
            }
        }
    }

    // Wire assignments: `x := y` or `x := sanitize(y)`.
    for assignment in &annotations.assignments {
        let Some(target) = decl_nodes.get(&(assignment.scope, Arc::clone(&assignment.lhs))) else {
            continue;
        };
        if assignment.from_source_or_sanitizer {
            // The source/sanitizer node already has an edge to the target.
            continue;
        }
        for name in referenced_identifiers(&assignment.rhs_text) {
            if let Some(source_id) =
                resolve_variable(&decl_nodes, &scope_by_id, assignment.byte_range.start, name)
            {
                graph.add_edge(source_id, *target, EdgeKind::Assignment);
            }
        }
    }

    graph
}

/// Resolve a variable name at a given byte offset to its declaration node,
/// climbing the scope tree as needed.
fn wire_arguments(
    graph: &mut TaintGraph,
    decl_nodes: &HashMap<(ScopeId, SharedText), TaintNodeId>,
    scope_by_id: &HashMap<ScopeId, &ScopeInfo>,
    node_id: TaintNodeId,
    byte_offset: usize,
    arguments: &[SharedText],
) {
    for (idx, arg) in arguments.iter().enumerate() {
        if let Some(arg_var) = as_simple_identifier(arg) {
            if let Some(source_id) = resolve_variable(decl_nodes, scope_by_id, byte_offset, arg_var)
            {
                graph.add_edge(source_id, node_id, EdgeKind::Argument(idx));
            }
        }
    }
}

fn resolve_variable(
    decl_nodes: &HashMap<(ScopeId, SharedText), TaintNodeId>,
    scope_by_id: &HashMap<ScopeId, &ScopeInfo>,
    byte_offset: usize,
    name: &str,
) -> Option<TaintNodeId> {
    // Find the innermost scope containing the byte offset.
    let mut current = scope_by_id
        .values()
        .filter(|s| s.byte_range.start <= byte_offset && byte_offset < s.byte_range.end)
        .min_by_key(|s| s.byte_range.end - s.byte_range.start)?;

    loop {
        let key = (current.id, Arc::from(name));
        if let Some(id) = decl_nodes.get(&key) {
            return Some(*id);
        }
        current = scope_by_id.get(&current.parent?)?;
    }
}

/// Naive identifier extraction from an RHS expression.
fn referenced_identifiers(expr: &str) -> Vec<&str> {
    // Split on non-identifier characters and return plausible identifiers.
    let mut out = Vec::new();
    for token in expr.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if !token.is_empty()
            && token.parse::<i64>().is_err()
            && !is_go_keyword(token)
            && token.len() < 256
        {
            out.push(token);
        }
    }
    out
}

fn is_go_keyword(token: &str) -> bool {
    matches!(
        token,
        "break"
            | "case"
            | "chan"
            | "const"
            | "continue"
            | "default"
            | "defer"
            | "else"
            | "fallthrough"
            | "for"
            | "func"
            | "go"
            | "goto"
            | "if"
            | "import"
            | "interface"
            | "map"
            | "package"
            | "range"
            | "return"
            | "select"
            | "struct"
            | "switch"
            | "type"
            | "var"
            | "string"
            | "int"
            | "bool"
            | "true"
            | "false"
            | "nil"
    )
}

fn as_simple_identifier(text: &str) -> Option<&str> {
    if text.is_empty() {
        return None;
    }
    if text.chars().all(|c| c.is_alphanumeric() || c == '_') && text.parse::<i64>().is_err() {
        return Some(text);
    }
    None
}

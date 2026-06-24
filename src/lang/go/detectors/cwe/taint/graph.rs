//! Build and query the intra-procedural taint graph.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use super::{
    EdgeKind, SanitizerKind, ScopeId, ScopeInfo, SharedText, SinkKind, SourceKind,
    TaintAnnotations, TaintGraph, TaintNode, TaintNodeId,
};

/// A discovered taint path from a source to a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintPath {
    pub source_id: TaintNodeId,
    pub sink_id: TaintNodeId,
    pub node_ids: Vec<TaintNodeId>,
    pub sanitized: bool,
}

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
            && !token.parse::<i64>().is_ok()
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

/// Find taint paths from any source of `source_kind` to any sink of `sink_kind`
/// within the same function scope. A path is "sanitized" if every path from the
/// source to the sink passes through an allowed sanitizer. If any unsanitized
/// path exists, the reported path is unsanitized.
pub fn find_taint_paths(
    graph: &TaintGraph,
    source_kind: SourceKind,
    sink_kind: SinkKind,
    allowed_sanitizers: &[SanitizerKind],
) -> Vec<TaintPath> {
    let source_ids: Vec<TaintNodeId> = graph
        .by_source
        .get(&source_kind)
        .cloned()
        .unwrap_or_default();
    let sink_ids: Vec<TaintNodeId> = graph.by_sink.get(&sink_kind).cloned().unwrap_or_default();

    let mut paths = Vec::new();
    for sink_id in sink_ids {
        if let Some(path) = bfs_path(graph, &source_ids, sink_id, allowed_sanitizers) {
            paths.push(path);
        }
    }
    paths
}

fn bfs_path(
    graph: &TaintGraph,
    source_ids: &[TaintNodeId],
    sink_id: TaintNodeId,
    allowed_sanitizers: &[SanitizerKind],
) -> Option<TaintPath> {
    // Build adjacency list for forward traversal.
    let mut adj: HashMap<TaintNodeId, Vec<TaintNodeId>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from).or_default().push(edge.to);
    }

    // State: (node, sanitized) -> visited. We want to find an unsanitized path
    // first; if none exists, accept a sanitized path.
    let mut queue: VecDeque<(TaintNodeId, bool, Vec<TaintNodeId>)> = VecDeque::new();
    let mut visited: HashSet<(TaintNodeId, bool)> = HashSet::new();

    for &source_id in source_ids {
        let sanitized = is_sanitizer(graph, source_id, allowed_sanitizers);
        queue.push_back((source_id, sanitized, vec![source_id]));
        visited.insert((source_id, sanitized));
    }

    let mut best_sanitized_path: Option<Vec<TaintNodeId>> = None;

    while let Some((current, sanitized, path)) = queue.pop_front() {
        if current == sink_id {
            if !sanitized {
                return Some(TaintPath {
                    source_id: path[0],
                    sink_id,
                    node_ids: path,
                    sanitized: false,
                });
            }
            if best_sanitized_path.is_none() {
                best_sanitized_path = Some(path.clone());
            }
            continue;
        }

        for &next in adj.get(&current).unwrap_or(&Vec::new()) {
            let next_sanitized = sanitized || is_sanitizer(graph, next, allowed_sanitizers);
            if visited.insert((next, next_sanitized)) {
                let mut next_path = path.clone();
                next_path.push(next);
                queue.push_back((next, next_sanitized, next_path));
            }
        }
    }

    best_sanitized_path.map(|path| TaintPath {
        source_id: path[0],
        sink_id,
        node_ids: path,
        sanitized: true,
    })
}

fn is_sanitizer(graph: &TaintGraph, node_id: TaintNodeId, allowed: &[SanitizerKind]) -> bool {
    matches!(
        graph.nodes.get(node_id),
        Some(TaintNode::Sanitizer { kind, .. }) if allowed.contains(kind)
    )
}

#[cfg(test)]
mod tests {
    use super::super::extract::extract_taint_facts;
    use super::*;
    use crate::core::ParsedUnit;

    fn parse(source: &str) -> ParsedUnit {
        crate::lang::go::parser::parse_go(source).expect("valid Go")
    }

    #[test]
    fn finds_sql_injection_path() {
        let source = r#"package main
func lookup(db *sql.DB, r *http.Request) {
    name := r.URL.Query().Get("name")
    _ = db.Query(name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::SQLQuery,
            &[SanitizerKind::SQL],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }

    #[test]
    fn finds_path_traversal_path() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    _ = os.Open(path)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::FileOpen,
            &[SanitizerKind::Path],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }
    #[test]
    fn finds_command_injection_path() {
        let source = r#"package main
func run(r *http.Request) {
    name := r.URL.Query().Get("cmd")
    exec.Command("sh", "-c", name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::CommandExec,
            &[SanitizerKind::Path],
        );
        assert_eq!(paths.len(), 1);
        assert!(!paths[0].sanitized);
    }

    #[test]
    fn sanitized_command_injection_path_is_flagged_as_sanitized() {
        let source = r#"package main
func run(r *http.Request) {
    raw := r.URL.Query().Get("cmd")
    name := filepath.Clean(raw)
    exec.Command("sh", "-c", name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        let graph = build_taint_graph(&facts);
        let paths = find_taint_paths(
            &graph,
            SourceKind::UserInput,
            SinkKind::CommandExec,
            &[SanitizerKind::Path],
        );
        assert_eq!(paths.len(), 1);
        assert!(paths[0].sanitized);
    }
}

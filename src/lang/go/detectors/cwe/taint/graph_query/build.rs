//! Build a `TaintGraph` from raw annotations.

use std::collections::HashMap;
use std::sync::Arc;

use super::super::{
    EdgeKind, ScopeId, ScopeInfo, ScopeKind, SharedText, TaintAnnotations, TaintGraph, TaintNode,
    TaintNodeId,
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

    // Create variable nodes for function parameters.
    for (_func_name, params) in &annotations.function_params {
        let func_scope = annotations.scopes.iter().find(|s| {
            s.kind == ScopeKind::Function
                && s.function.as_ref().is_some_and(|f| f.as_ref() == _func_name.as_ref())
        });
        let Some(func_scope) = func_scope else {
            continue;
        };
        for param in params {
            let node = TaintNode::Variable {
                name: Arc::clone(param),
                type_hint: None,
                scope: func_scope.id,
                decl_byte: func_scope.byte_range.start,
            };
            let id = graph.add_node(node);
            decl_nodes.insert((func_scope.id, Arc::clone(param)), id);
        }
    }

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
        // Wire any identifier argument (including inside compound expressions
        // like `"prefix" + tainted`) to its declaring variable.
        for (idx, arg) in sink.all_arguments.iter().enumerate() {
            for name in referenced_identifiers(arg) {
                if let Some(source_id) =
                    resolve_variable(&decl_nodes, &scope_by_id, sink.byte_range.start, name)
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

        // ponytail: skip assignment edges when RHS is an opaque function call
        // (e.g. `safe := callee(x)`).  These create false edges from argument
        // variables to result variables, incorrectly propagating taint through
        // functions whose semantics we don't know.  Known sources, sinks, and
        // sanitizers are handled via their own nodes above.
        let call_name = assignment.rhs_text.split('(').next().map(str::trim).unwrap_or("");
        let is_opaque_call = assignment.rhs_text.contains('(')
            && !is_source_or_sanitizer_assignment(&assignment.rhs_text)
            && !is_known_propagator(call_name);
        if is_opaque_call {
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
        for name in referenced_identifiers(arg) {
            if let Some(source_id) = resolve_variable(decl_nodes, scope_by_id, byte_offset, name) {
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

/// Check if the RHS text represents a call to a known source or sanitizer.
fn is_source_or_sanitizer_assignment(rhs: &str) -> bool {
    let call_name = rhs.split('(').next().map(str::trim).unwrap_or("");
    if call_name.is_empty() {
        return false;
    }
    let is_source = call_name.contains(".URL.Query")
        || call_name.contains(".FormValue")
        || call_name.contains(".PostForm")
        || call_name.contains(".Header.Get")
        || call_name.contains(".GetRawData")
        || call_name.ends_with(".PathValue")
        || call_name.ends_with(".Param")
        || call_name == "c.Query"
        || call_name == "c.DefaultQuery"
        || call_name == "c.QueryArray"
        || call_name == "os.Args"
        || call_name == "flag.Args"
        || call_name == "flag.String"
        || call_name == "os.Getenv"
        || call_name == "os.LookupEnv"
        || call_name == "io.ReadAll";
    if is_source {
        return true;
    }
    let is_sanitizer = call_name == "filepath.Clean"
        || call_name == "path.Clean"
        || call_name == "filepath.Base"
        || call_name == "html.EscapeString"
        || call_name == "html.UnescapeString"
        || call_name == "url.QueryEscape"
        || call_name == "url.PathEscape"
        || call_name == "ldap.EscapeFilter"
        || call_name == "xml.EscapeText"
        || call_name == "xml.Marshal"
        || call_name.ends_with(".Prepare");
    if is_sanitizer {
        return true;
    }
    if let Some(name) = call_name.rsplit('.').next() {
        let lower = name.to_lowercase();
        if lower.starts_with("sanitize")
            || lower.starts_with("clean")
            || lower.starts_with("escape")
            || lower.starts_with("validate")
            || lower.starts_with("purify")
        {
            return true;
        }
    }
    false
}

/// Known taint propagators — functions that pass taint from arguments to
/// return values without sanitizing.  These should NOT be treated as opaque.
// ponytail: a lazy_static BUILTIN_SUMMARIES table would also provide
// pre-computed summaries for cross-function callee lookups; deferred until
// a real need arises — opaque-call heuristic covers the common case.
fn is_known_propagator(func_name: &str) -> bool {
    matches!(
        func_name,
        "filepath.Join"
            | "strings.Join"
            | "strings.Replace"
            | "strings.Repeat"
            | "strings.Trim"
            | "strings.TrimSpace"
            | "fmt.Sprintf"
            | "fmt.Errorf"
            | "path.Join"
            | "append"
            | "json.Marshal"
            | "strconv.Itoa"
            | "strconv.FormatInt"
    )
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

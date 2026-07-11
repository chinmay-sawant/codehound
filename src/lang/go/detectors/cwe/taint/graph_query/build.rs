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

    // Versioned last-write: each assignment gets its own node; resolve picks
    // the latest decl with `decl_byte <= use_byte` (not pure overwrite).
    // Key is (scope, name) including field-qualified names (`user.Path`).
    let mut decl_nodes: HashMap<(ScopeId, SharedText), Vec<(usize, TaintNodeId)>> = HashMap::new();

    // Index scopes by id for parent lookups.
    let scope_by_id: HashMap<ScopeId, &ScopeInfo> =
        annotations.scopes.iter().map(|s| (s.id, s)).collect();

    // Create variable nodes for function parameters.
    for (_func_name, params) in &annotations.function_params {
        let func_scope = annotations.scopes.iter().find(|s| {
            s.kind == ScopeKind::Function
                && s.function
                    .as_ref()
                    .is_some_and(|f| f.as_ref() == _func_name.as_ref())
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
            decl_nodes
                .entry((func_scope.id, Arc::clone(param)))
                .or_default()
                .push((func_scope.byte_range.start, id));
        }
    }

    // Create variable nodes for every non-channel assignment (versioned).
    for assignment in &annotations.assignments {
        if assignment.is_channel_send {
            continue;
        }
        let node = TaintNode::Variable {
            name: Arc::clone(&assignment.lhs),
            type_hint: None,
            scope: assignment.scope,
            decl_byte: assignment.byte_range.start,
        };
        let id = graph.add_node(node);
        decl_nodes
            .entry((assignment.scope, Arc::clone(&assignment.lhs)))
            .or_default()
            .push((assignment.byte_range.start, id));
    }

    // Keep versions sorted by decl_byte for binary search / last-write.
    for versions in decl_nodes.values_mut() {
        versions.sort_by_key(|(byte, _)| *byte);
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
        // Wire any identifier / field key argument (including inside compound
        // expressions like `"prefix" + tainted`) to its declaring variable.
        for (idx, arg) in sink.all_arguments.iter().enumerate() {
            for name in referenced_names(arg) {
                if let Some(source_id) =
                    resolve_variable(&decl_nodes, &scope_by_id, sink.byte_range.start, name)
                {
                    graph.add_edge(source_id, id, EdgeKind::Argument(idx));
                }
            }
        }

        // ponytail: pointer bridge for deserialization output args
        // (json.Unmarshal, xml.Unmarshal).  Wire assignment edges from
        // input argument variables to the output pointer variable so
        // taint flows through the deserialized result.
        let out_args = tainted_output_args(&sink.function);
        if !out_args.is_empty() {
            for &out_idx in out_args {
                let out_text = match sink.all_arguments.get(out_idx) {
                    Some(t) => t,
                    None => continue,
                };
                let out_names = referenced_names(out_text);
                for (in_idx, in_arg) in sink.all_arguments.iter().enumerate() {
                    if in_idx == out_idx {
                        continue;
                    }
                    for in_name in referenced_names(in_arg) {
                        for out_name in &out_names {
                            if let (Some(src), Some(dst)) = (
                                resolve_variable(
                                    &decl_nodes,
                                    &scope_by_id,
                                    sink.byte_range.start,
                                    in_name,
                                ),
                                resolve_variable(
                                    &decl_nodes,
                                    &scope_by_id,
                                    sink.byte_range.start,
                                    out_name,
                                ),
                            ) {
                                graph.add_edge(src, dst, EdgeKind::Assignment);
                            }
                        }
                    }
                }
            }
        }
    }

    // Wire assignments: `x := y` or `x := sanitize(y)`.
    for assignment in &annotations.assignments {
        if assignment.is_channel_send {
            continue;
        }
        let Some(target) = resolve_decl_at(
            &decl_nodes,
            assignment.scope,
            assignment.lhs.as_ref(),
            assignment.byte_range.start,
        ) else {
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
        let call_name = assignment
            .rhs_text
            .split('(')
            .next()
            .map(str::trim)
            .unwrap_or("");
        let is_opaque_call = assignment.rhs_text.contains('(')
            && !is_source_or_sanitizer_assignment(&assignment.rhs_text)
            && !is_known_propagator(call_name);
        if is_opaque_call {
            continue;
        }

        for name in referenced_names(&assignment.rhs_text) {
            if let Some(source_id) =
                resolve_variable(&decl_nodes, &scope_by_id, assignment.byte_range.start, name)
            {
                graph.add_edge(source_id, target, EdgeKind::Assignment);
            }
        }
    }

    // Map/slice index: conservative whole-base taint (`m[k] = t` taints `m`).
    // Per-key precision is intentionally low-confidence / not modeled.
    for assignment in &annotations.assignments {
        if assignment.is_channel_send {
            continue;
        }
        if let Some(bracket) = assignment.lhs.find('[') {
            let base = assignment.lhs[..bracket].trim();
            if let Some(base_id) = resolve_decl_at(
                &decl_nodes,
                assignment.scope,
                base,
                assignment.byte_range.start,
            ) {
                if !assignment.from_source_or_sanitizer {
                    for name in referenced_names(&assignment.rhs_text) {
                        if let Some(source_id) = resolve_variable(
                            &decl_nodes,
                            &scope_by_id,
                            assignment.byte_range.start,
                            name,
                        ) {
                            graph.add_edge(source_id, base_id, EdgeKind::Assignment);
                        }
                    }
                }
            }
        }
    }

    graph
}

/// Resolve a variable name at a given byte offset to its declaration node,
/// climbing the scope tree as needed.
fn wire_arguments(
    graph: &mut TaintGraph,
    decl_nodes: &HashMap<(ScopeId, SharedText), Vec<(usize, TaintNodeId)>>,
    scope_by_id: &HashMap<ScopeId, &ScopeInfo>,
    node_id: TaintNodeId,
    byte_offset: usize,
    arguments: &[SharedText],
) {
    for (idx, arg) in arguments.iter().enumerate() {
        for name in referenced_names(arg) {
            if let Some(source_id) = resolve_variable(decl_nodes, scope_by_id, byte_offset, name) {
                graph.add_edge(source_id, node_id, EdgeKind::Argument(idx));
            }
        }
    }
}

/// Latest version of `name` in `scope` with `decl_byte <= use_byte`.
fn resolve_decl_at(
    decl_nodes: &HashMap<(ScopeId, SharedText), Vec<(usize, TaintNodeId)>>,
    scope: ScopeId,
    name: &str,
    use_byte: usize,
) -> Option<TaintNodeId> {
    let versions = decl_nodes.get(&(scope, Arc::from(name)))?;
    versions
        .iter()
        .rev()
        .find(|(byte, _)| *byte <= use_byte)
        .map(|(_, id)| *id)
}

fn resolve_variable(
    decl_nodes: &HashMap<(ScopeId, SharedText), Vec<(usize, TaintNodeId)>>,
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
        // Prefer field-qualified key, then climb scopes for last-write version.
        if let Some(id) = resolve_decl_at(decl_nodes, current.id, name, byte_offset) {
            return Some(id);
        }
        // If name is `base.field`, also try base alone (conservative).
        if let Some((base, _)) = name.split_once('.') {
            if let Some(id) = resolve_decl_at(decl_nodes, current.id, base, byte_offset) {
                return Some(id);
            }
        }
        current = scope_by_id.get(&current.parent?)?;
    }
}

/// Identifiers **and** field-access chains (`user.Path`) from an expression.
fn referenced_names(expr: &str) -> Vec<&str> {
    let mut out = referenced_identifiers(expr);
    // Also collect `ident.field` / `ident.field.field` as whole keys.
    let mut start = 0usize;
    let bytes = expr.as_bytes();
    while start < bytes.len() {
        // skip non-ident
        while start < bytes.len()
            && !(bytes[start].is_ascii_alphabetic() || bytes[start] == b'_')
        {
            start += 1;
        }
        if start >= bytes.len() {
            break;
        }
        let mut end = start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || bytes[end] == b'_'
                || bytes[end] == b'.')
        {
            end += 1;
        }
        // trim trailing dots
        while end > start && bytes[end - 1] == b'.' {
            end -= 1;
        }
        let token = &expr[start..end];
        if token.contains('.')
            && !token.is_empty()
            && !out.iter().any(|t| *t == token)
            && token.len() < 256
        {
            out.push(token);
        }
        start = end.max(start + 1);
    }
    out
}

/// Naive identifier extraction from an RHS expression.
fn referenced_identifiers(expr: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut token_start: Option<usize> = None;
    let mut quote: Option<char> = None;
    let mut escaped = false;

    fn push_token<'a>(
        expr: &'a str,
        token_start: &mut Option<usize>,
        end: usize,
        out: &mut Vec<&'a str>,
    ) {
        let Some(start) = token_start.take() else {
            return;
        };
        let token = &expr[start..end];
        if !token.is_empty()
            && token.parse::<i64>().is_err()
            && !is_go_keyword(token)
            && token.len() < 256
        {
            out.push(token);
        }
    }

    for (idx, ch) in expr.char_indices() {
        if let Some(active_quote) = quote {
            match active_quote {
                '`' if ch == '`' => quote = None,
                '"' | '\'' if escaped => escaped = false,
                '"' | '\'' if ch == '\\' => escaped = true,
                q if ch == q => quote = None,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' | '\'' | '`' => {
                push_token(expr, &mut token_start, idx, &mut out);
                quote = Some(ch);
                escaped = false;
            }
            ch if ch.is_alphanumeric() || ch == '_' => {
                if token_start.is_none() {
                    token_start = Some(idx);
                }
            }
            _ => push_token(expr, &mut token_start, idx, &mut out),
        }
    }

    push_token(expr, &mut token_start, expr.len(), &mut out);
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
    // Align with classify_sanitizer: Clean/Prepare are not path/SQL safe alone.
    let is_sanitizer = call_name == "filepath.Base"
        || call_name == "html.EscapeString"
        || call_name == "html.UnescapeString"
        || call_name == "url.QueryEscape"
        || call_name == "url.PathEscape"
        || call_name == "ldap.EscapeFilter"
        || call_name == "xml.EscapeText"
        || call_name == "xml.Marshal";
    if is_sanitizer {
        return true;
    }
    if let Some(name) = call_name.rsplit('.').next() {
        let lower = name.to_lowercase();
        if lower.starts_with("sanitize")
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
/// Known functions whose pointer arguments receive tainted data.
/// Returns the argument indices that are output pointers (written to by
/// the function).  The graph builder creates Assignment edges from input
/// argument variables to these output variables.
// ponytail: only handles json.Unmarshal/xml.Unmarshal.  (*Decoder).Decode
// is deferred — the receiver-based taint origin needs type inference.
fn tainted_output_args(func_name: &str) -> &[usize] {
    if func_name == "json.Unmarshal" || func_name == "xml.Unmarshal" {
        return &[0];
    }
    &[]
}

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

#[cfg(test)]
mod tests {
    use super::referenced_identifiers;

    #[test]
    fn referenced_identifiers_ignores_string_literals() {
        let ids = referenced_identifiers(r#"[]byte(`{"db":"up"}`)"#);
        assert!(
            !ids.contains(&"db"),
            "string literals should not create taint edges: {ids:?}"
        );
    }

    #[test]
    fn referenced_identifiers_keeps_real_identifiers() {
        let ids = referenced_identifiers(r#"fmt.Sprintf("user=%s", userID) + suffix"#);
        assert!(ids.contains(&"fmt"));
        assert!(ids.contains(&"Sprintf"));
        assert!(ids.contains(&"userID"));
        assert!(ids.contains(&"suffix"));
        assert!(!ids.contains(&"user"));
    }
}

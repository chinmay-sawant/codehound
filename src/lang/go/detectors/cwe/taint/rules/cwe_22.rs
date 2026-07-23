//! Detect CWE-22 (Path Traversal) via taint flow.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::cwe::facts::GoUnitFacts;
use crate::lang::go::detectors::cwe::metadata::META_CWE_22;
use crate::rules::emit;
use crate::rules::{DetectorEvidence, Finding, TaintSinkInfo};

use super::super::{
    EdgeKind, SanitizerKind, SinkKind, SourceKind, TaintGraph, TaintNode, TaintPath,
    find_taint_paths,
};
use super::evidence::source_info;

pub fn detect_cwe_22_taint(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let Some(graph) = &facts.taint_graph else {
        return;
    };
    let file = unit.display_path.as_str();

    let paths = find_taint_paths(
        graph,
        SourceKind::UserInput,
        SinkKind::FileOpen,
        &[SanitizerKind::Path],
    );

    for path in paths {
        if path.sanitized {
            continue;
        }

        // A `HasPrefix` elsewhere in the file is not a sanitizer. Suppress
        // only for a lexical, terminating guard on this exact tainted binding.
        if is_path_confined(unit, facts, &path, graph) {
            continue;
        }

        // ponytail: only flag when the taint flows through the FIRST argument
        // (file path). Taint in other arguments (file content, mode, flags) is
        // not path traversal. Upgrade: pre-compute this in the taint path query.
        if !is_first_arg_tainted(graph, &path) {
            continue;
        }

        let Some(TaintNode::Sink {
            function: sink_fn,
            byte_range: sink_range,
            ..
        }) = graph.nodes.get(path.sink_id)
        else {
            continue;
        };
        let (line, col) = unit.line_col(sink_range.start);
        let at = out.len();
        emit::push_finding_with_evidence(
            &META_CWE_22,
            file,
            line,
            col,
            "user-controlled input reaches a file-open sink without path sanitization",
            DetectorEvidence::TaintFlow {
                source: source_info(graph, &path),
                sink: TaintSinkInfo::new("FileOpen", sink_fn.to_string()),
                hops: path.node_ids.len().saturating_sub(1),
                sanitized: false,
            },
            out,
        );
        // Taint-core confidence higher than needle heuristics.
        for f in out.iter_mut().skip(at) {
            f.confidence = Some(0.75);
        }
    }
}

/// Check whether the taint flows through argument 0 (file path) of the sink.
fn is_first_arg_tainted(graph: &TaintGraph, path: &TaintPath) -> bool {
    for node_id in &path.node_ids {
        for edge in &graph.edges {
            if edge.from == *node_id
                && edge.to == path.sink_id
                && matches!(edge.kind, EdgeKind::Argument(0))
            {
                return true;
            }
        }
    }
    false
}

/// Confinement requires a preceding `if !strings.HasPrefix(binding, ...) {
/// return }` in the binding's lexical scope. This deliberately declines more
/// sophisticated guards until taint propagation models control flow.
fn is_path_confined(
    unit: &ParsedUnit,
    facts: &GoUnitFacts,
    path: &TaintPath,
    graph: &TaintGraph,
) -> bool {
    let Some(TaintNode::Sink { byte_range, .. }) = graph.nodes.get(path.sink_id) else {
        return false;
    };
    for node_id in &path.node_ids {
        if let Some(TaintNode::Variable {
            name,
            scope,
            decl_byte,
            ..
        }) = graph.nodes.get(*node_id)
        {
            let Some(scope_info) = facts.taint.scopes.iter().find(|info| info.id == *scope) else {
                continue;
            };
            if *decl_byte < byte_range.start
                && has_terminating_prefix_guard(
                    unit.tree.root_node(),
                    unit.source.as_ref(),
                    name,
                    *decl_byte,
                    byte_range.start,
                    scope_info,
                )
            {
                return true;
            }
        }
    }
    false
}

fn has_terminating_prefix_guard(
    root: tree_sitter::Node,
    source: &str,
    binding: &str,
    decl_byte: usize,
    sink_byte: usize,
    binding_scope: &super::super::ScopeInfo,
) -> bool {
    let mut cursor = root.walk();
    find_terminating_prefix_guard(
        root,
        &mut cursor,
        source,
        binding,
        decl_byte,
        sink_byte,
        binding_scope,
    )
}

#[allow(clippy::too_many_arguments)]
fn find_terminating_prefix_guard(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    source: &str,
    binding: &str,
    decl_byte: usize,
    sink_byte: usize,
    binding_scope: &super::super::ScopeInfo,
) -> bool {
    if node.kind() == "if_statement"
        && node.start_byte() >= decl_byte
        && node.end_byte() <= sink_byte
        && guard_shares_binding_scope(node, binding_scope)
        && guard_checks_binding(node, source, binding)
        && guard_terminates(node)
    {
        return true;
    }

    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if find_terminating_prefix_guard(
                child,
                cursor,
                source,
                binding,
                decl_byte,
                sink_byte,
                binding_scope,
            ) {
                cursor.goto_parent();
                return true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
    false
}

fn guard_shares_binding_scope(
    guard: tree_sitter::Node,
    binding_scope: &super::super::ScopeInfo,
) -> bool {
    let Some(parent) = guard.parent() else {
        return false;
    };
    let block = if parent.kind() == "statement_list" {
        match parent.parent() {
            Some(block) => block,
            None => return false,
        }
    } else {
        parent
    };
    if block.kind() != "block" {
        return false;
    }
    if block.start_byte() == binding_scope.byte_range.start
        && block.end_byte() == binding_scope.byte_range.end
    {
        return true;
    }
    // Parameters belong to the function scope while their guards live in the
    // direct body block. Do not accept nested blocks for a parameter binding.
    matches!(binding_scope.kind, super::super::ScopeKind::Function)
        && block.parent().is_some_and(|function| {
            matches!(
                function.kind(),
                "function_declaration" | "method_declaration" | "func_literal"
            ) && function.start_byte() == binding_scope.byte_range.start
                && function.end_byte() == binding_scope.byte_range.end
        })
}

fn guard_checks_binding(guard: tree_sitter::Node, source: &str, binding: &str) -> bool {
    let Ok(text) = guard.utf8_text(source.as_bytes()) else {
        return false;
    };
    let Some(arguments) = text.trim().strip_prefix("if !strings.HasPrefix(") else {
        return false;
    };
    arguments
        .split_once(',')
        .is_some_and(|(first, _)| first.trim() == binding)
}

fn guard_terminates(guard: tree_sitter::Node) -> bool {
    let mut cursor = guard.walk();
    let Some(consequence) = guard
        .named_children(&mut cursor)
        .find(|child| child.kind() == "block")
    else {
        return false;
    };
    let mut cursor = consequence.walk();
    let mut statements = consequence.named_children(&mut cursor);
    let Some(statement_list) = statements.find(|child| child.kind() == "statement_list") else {
        return false;
    };
    let mut cursor = statement_list.walk();
    statement_list
        .named_children(&mut cursor)
        .last()
        .is_some_and(|statement| statement.kind() == "return_statement")
}

#[cfg(test)]
mod tests {
    use crate::lang::go::detectors::cwe::facts::{
        FactBuildOpts, build_go_unit_facts_with, build_taint_graph_for_facts,
    };
    use crate::lang::go::detectors::cwe::taint::extract::classify_sanitizer;

    use super::*;

    fn cwe_22_findings(source: &str) -> usize {
        let unit = crate::lang::parser::parse_go(source).expect("valid Go");
        let mut facts = build_go_unit_facts_with(&unit, FactBuildOpts::TAINT);
        build_taint_graph_for_facts(&mut facts);
        let mut findings = Vec::new();
        detect_cwe_22_taint(&unit, &facts, &mut findings);
        findings.len()
    }

    #[test]
    fn unescape_string_does_not_sanitize_html_taint() {
        assert!(classify_sanitizer("html.UnescapeString").is_none());
    }

    #[test]
    fn unrelated_prefix_check_does_not_suppress_path_taint() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    other := "/safe"
    if !strings.HasPrefix(other, "/safe") { return }
    os.Open(path)
}"#;
        assert_eq!(cwe_22_findings(source), 1);
    }

    #[test]
    fn terminating_same_binding_prefix_guard_suppresses_path_taint() {
        let source = r#"package main
func serve(r *http.Request) {
    path := r.URL.Query().Get("path")
    if !strings.HasPrefix(path, "/safe/") { return }
    os.Open(path)
}"#;
        assert_eq!(cwe_22_findings(source), 0);
    }
}

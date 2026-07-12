use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use crate::core::ParsedUnit;

use super::super::{
    AssignmentDetail, ScopeId, ScopeInfo, ScopeKind, SharedText, TaintAnnotations,
    TaintSanitizerAnnotation, TaintSinkAnnotation, TaintSourceAnnotation, UnsupportedFlow,
};
use super::walker_records::{record_assignment, record_call, record_go_stmt, record_send};

/// Extract taint annotations from a parsed Go source unit.
pub fn extract_taint_facts(unit: &ParsedUnit) -> TaintAnnotations {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut state = ExtractionState::new(unit.source.as_ref());

    let mut cursor = root.walk();
    walk_node(root, &mut cursor, src, &mut state);

    TaintAnnotations {
        sources: state.sources,
        sinks: state.sinks,
        sanitizers: state.sanitizers,
        assignments: state.assignments,
        scopes: state.scopes,
        function_params: state.function_params,
        function_ranges: state.function_ranges,
        unsupported_flows: state.unsupported_flows,
    }
}

pub(super) struct ExtractionState<'a> {
    pub(super) src_bytes: &'a [u8],
    pub(super) scopes: Vec<ScopeInfo>,
    pub(super) scope_stack: Vec<ScopeId>,
    pub(super) next_scope_id: ScopeId,
    pub(super) current_function: Option<SharedText>,
    pub(super) sources: Vec<TaintSourceAnnotation>,
    pub(super) sinks: Vec<TaintSinkAnnotation>,
    pub(super) sanitizers: Vec<TaintSanitizerAnnotation>,
    pub(super) assignments: Vec<AssignmentDetail>,
    pub(super) function_params: HashMap<SharedText, Vec<SharedText>>,
    pub(super) function_ranges: HashMap<SharedText, Range<usize>>,
    pub(super) unsupported_flows: Vec<UnsupportedFlow>,
}

impl<'a> ExtractionState<'a> {
    pub(super) fn new(source: &'a str) -> Self {
        Self {
            src_bytes: source.as_bytes(),
            scopes: Vec::new(),
            scope_stack: Vec::new(),
            next_scope_id: 0,
            current_function: None,
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            assignments: Vec::new(),
            function_params: HashMap::new(),
            function_ranges: HashMap::new(),
            unsupported_flows: Vec::new(),
        }
    }

    pub(super) fn push_scope(&mut self, kind: ScopeKind, byte_range: Range<usize>) -> ScopeId {
        let id = self.next_scope_id;
        self.next_scope_id += 1;
        let parent = self.scope_stack.last().copied();
        self.scopes.push(ScopeInfo {
            id,
            parent,
            kind,
            byte_range,
            function: self.current_function.clone(),
        });
        self.scope_stack.push(id);
        id
    }

    pub(super) fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    pub(super) fn current_scope(&self) -> ScopeId {
        self.scope_stack
            .last()
            .copied()
            .expect("scope stack must never be empty at root")
    }
}

pub(super) fn walk_node(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    src: &[u8],
    state: &mut ExtractionState<'_>,
) {
    let mut entered_scope = None;

    match node.kind() {
        "function_declaration" | "func_literal" | "method_declaration" => {
            let func_name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or("<anonymous>");
            let func_name: SharedText = Arc::from(func_name);
            state.current_function = Some(func_name.clone());
            // Extract parameter names for TaintSummary computation.
            let params = extract_param_names(node, src);
            state.function_params.insert(func_name.clone(), params);
            state
                .function_ranges
                .insert(func_name.clone(), node.start_byte()..node.end_byte());
            entered_scope = Some((
                ScopeKind::Function,
                node.start_byte()..node.end_byte(),
                Some(func_name),
            ));
        }
        "block" => {
            entered_scope = Some((
                ScopeKind::Block,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "if_statement" => {
            entered_scope = Some((
                ScopeKind::If,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "for_statement" | "range_clause" => {
            entered_scope = Some((
                ScopeKind::For,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "switch_statement" | "expression_switch_statement" => {
            entered_scope = Some((
                ScopeKind::Switch,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "case_clause" | "default_case" => {
            entered_scope = Some((
                ScopeKind::Case,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "call_expression" => {
            record_call(node, state);
        }
        "send_statement" => {
            record_send(node, state);
        }
        "go_statement" => {
            record_go_stmt(node, state);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment(node, state);
        }
        _ => {}
    }

    if let Some((kind, ref range, _)) = entered_scope {
        state.push_scope(kind, range.clone());
    }

    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            walk_node(child, cursor, src, state);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }

    if entered_scope.is_some() {
        state.pop_scope();
        if matches!(entered_scope, Some((ScopeKind::Function, _, _))) {
            state.current_function = None;
        }
    }
}

/// Extract parameter names from a function/method declaration node.
fn extract_param_names(node: tree_sitter::Node, src: &[u8]) -> Vec<SharedText> {
    let Some(params) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .filter_map(|p| {
            p.child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
                .map(Arc::from)
        })
        .collect()
}

pub(super) fn is_chained_call(func_node: tree_sitter::Node) -> bool {
    if func_node.kind() != "selector_expression" {
        return false;
    }
    let Some(operand) = func_node.child_by_field_name("operand") else {
        return false;
    };
    operand.kind() == "call_expression"
}

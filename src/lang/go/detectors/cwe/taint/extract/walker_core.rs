use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use crate::core::ParsedUnit;

use super::super::{
    AssignmentDetail, ChannelRecvSite, ChannelSendSite, ChannelTransfer, ScopeId, ScopeInfo,
    ScopeKind, SharedText, TaintAnnotations, TaintSanitizerAnnotation, TaintSinkAnnotation,
    TaintSourceAnnotation, UnsupportedFlow, UnsupportedFlowKind, normalize_receiver_type,
};
use super::walker_records::{
    record_assignment, record_call, record_go_stmt, record_select_receive, record_send,
};

/// Extract taint annotations from a parsed Go source unit.
pub fn extract_taint_facts(unit: &ParsedUnit) -> TaintAnnotations {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut state = ExtractionState::new(unit.source.as_ref());
    state.push_scope(ScopeKind::Package, 0..unit.source.len());

    let mut cursor = root.walk();
    walk_node(root, &mut cursor, src, &mut state);
    state.pop_scope();

    let (channel_transfers, mut unsupported) = pair_channel_transfers(
        &state.channel_sends,
        &state.channel_recvs,
        &state.assignments,
    );
    unsupported.append(&mut state.unsupported_flows);

    TaintAnnotations {
        sources: state.sources,
        sinks: state.sinks,
        sanitizers: state.sanitizers,
        assignments: state.assignments,
        scopes: state.scopes,
        function_params: state.function_params,
        function_ranges: state.function_ranges,
        unsupported_flows: unsupported,
        channel_transfers,
    }
}

pub(super) struct ExtractionState<'a> {
    pub(super) src_bytes: &'a [u8],
    pub(super) scopes: Vec<ScopeInfo>,
    pub(super) scope_stack: Vec<ScopeId>,
    pub(super) next_scope_id: ScopeId,
    pub(super) current_function: Option<SharedText>,
    pub(super) function_scope_stack: Vec<ScopeId>,
    pub(super) sources: Vec<TaintSourceAnnotation>,
    pub(super) sinks: Vec<TaintSinkAnnotation>,
    pub(super) sanitizers: Vec<TaintSanitizerAnnotation>,
    pub(super) assignments: Vec<AssignmentDetail>,
    pub(super) function_params: HashMap<SharedText, Vec<SharedText>>,
    pub(super) function_ranges: HashMap<SharedText, Range<usize>>,
    pub(super) unsupported_flows: Vec<UnsupportedFlow>,
    pub(super) channel_sends: Vec<ChannelSendSite>,
    pub(super) channel_recvs: Vec<ChannelRecvSite>,
}

impl<'a> ExtractionState<'a> {
    pub(super) fn new(source: &'a str) -> Self {
        Self {
            src_bytes: source.as_bytes(),
            scopes: Vec::new(),
            scope_stack: Vec::new(),
            next_scope_id: 0,
            current_function: None,
            function_scope_stack: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            assignments: Vec::new(),
            function_params: HashMap::new(),
            function_ranges: HashMap::new(),
            unsupported_flows: Vec::new(),
            channel_sends: Vec::new(),
            channel_recvs: Vec::new(),
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
        if kind == ScopeKind::Function {
            self.function_scope_stack.push(id);
        }
        id
    }

    pub(super) fn pop_scope(&mut self) {
        if let Some(id) = self.scope_stack.pop() {
            if self
                .scopes
                .get(id)
                .is_some_and(|s| s.kind == ScopeKind::Function)
            {
                self.function_scope_stack.pop();
            }
        }
    }

    pub(super) fn current_scope(&self) -> ScopeId {
        self.scope_stack
            .last()
            .copied()
            .expect("scope stack must never be empty at root")
    }

    /// Innermost function/method/func_literal scope, or package scope as fallback.
    pub(super) fn current_function_scope(&self) -> ScopeId {
        self.function_scope_stack
            .last()
            .copied()
            .unwrap_or_else(|| self.current_scope())
    }
}

pub(super) fn walk_node(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    src: &[u8],
    state: &mut ExtractionState<'_>,
) {
    let mut entered_scope = None;
    // A closure temporarily becomes the current function while its body is
    // traversed. Keep the enclosing identity so sibling statements after the
    // closure remain attributed to the outer function.
    let mut restore_function = None;

    match node.kind() {
        "function_declaration" | "func_literal" | "method_declaration" => {
            let func_name = function_identity(node, src);
            let previous_function = state.current_function.replace(func_name.clone());
            restore_function = Some(previous_function);
            // Extract parameter names for TaintSummary computation.
            let params = extract_param_names(node, src);
            state.function_params.insert(func_name.clone(), params);
            state
                .function_ranges
                .insert(func_name.clone(), node.start_byte()..node.end_byte());
            entered_scope = Some((ScopeKind::Function, node.start_byte()..node.end_byte()));
        }
        "block" => {
            entered_scope = Some((ScopeKind::Block, node.start_byte()..node.end_byte()));
        }
        "if_statement" => {
            entered_scope = Some((ScopeKind::If, node.start_byte()..node.end_byte()));
        }
        "for_statement" | "range_clause" => {
            entered_scope = Some((ScopeKind::For, node.start_byte()..node.end_byte()));
        }
        "switch_statement" | "expression_switch_statement" => {
            entered_scope = Some((ScopeKind::Switch, node.start_byte()..node.end_byte()));
        }
        "case_clause" | "default_case" => {
            entered_scope = Some((ScopeKind::Case, node.start_byte()..node.end_byte()));
        }
        "call_expression" => {
            record_call(node, state);
        }
        "send_statement" => {
            record_send(node, state);
        }
        "receive_statement" => {
            record_select_receive(node, state);
        }
        "go_statement" => {
            record_go_stmt(node, state);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment(node, state);
        }
        _ => {}
    }

    if let Some((kind, ref range)) = entered_scope {
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
    }
    if let Some(previous_function) = restore_function {
        state.current_function = previous_function;
    }
}

/// Stable identity for per-file function facts. Go permits same-named methods
/// on different receiver types, so a bare method name would overwrite a prior
/// method's parameter/range summary in a single source file.
fn function_identity(node: tree_sitter::Node, src: &[u8]) -> SharedText {
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(src).ok())
        .unwrap_or("<anonymous>");
    if node.kind() != "method_declaration" {
        return Arc::from(name);
    }
    let receiver = node
        .child_by_field_name("receiver")
        .and_then(|n| n.utf8_text(src).ok())
        .map(normalize_receiver_type)
        .filter(|receiver| !receiver.is_empty());
    match receiver {
        Some(receiver) => Arc::from(format!("{receiver}.{name}")),
        None => Arc::from(name),
    }
}

/// G5 v0 pairing: same lexical function, one channel binding, exactly one send
/// + one recv with an LHS → [`ChannelTransfer`]; else [`UnsupportedFlowKind::Channel`].
fn pair_channel_transfers(
    sends: &[ChannelSendSite],
    recvs: &[ChannelRecvSite],
    assignments: &[AssignmentDetail],
) -> (Vec<ChannelTransfer>, Vec<UnsupportedFlow>) {
    let mut transfers = Vec::new();
    let mut unsupported = Vec::new();

    // Key: (function_scope, channel name)
    let mut send_groups: HashMap<(ScopeId, SharedText), Vec<&ChannelSendSite>> = HashMap::new();
    for s in sends {
        send_groups
            .entry((s.function_scope, Arc::clone(&s.channel)))
            .or_default()
            .push(s);
    }
    let mut recv_groups: HashMap<(ScopeId, SharedText), Vec<&ChannelRecvSite>> = HashMap::new();
    for r in recvs {
        recv_groups
            .entry((r.function_scope, Arc::clone(&r.channel)))
            .or_default()
            .push(r);
    }

    let mut keys: Vec<(ScopeId, SharedText)> = send_groups
        .keys()
        .chain(recv_groups.keys())
        .cloned()
        .collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_ref().cmp(b.1.as_ref())));
    keys.dedup();

    for key in keys {
        let ss = send_groups.remove(&key).unwrap_or_default();
        let rs = recv_groups.remove(&key).unwrap_or_default();
        let channel = &key.1;

        let decline = ss.len() != 1
            || rs.len() != 1
            || ss[0].in_select
            || rs[0].in_select
            || rs[0].lhs.is_none()
            || channel_looks_buffered(assignments, channel.as_ref(), key.0);

        if decline {
            for s in ss {
                unsupported.push(UnsupportedFlow {
                    kind: UnsupportedFlowKind::Channel,
                    byte_range: s.byte_range.clone(),
                    note: Arc::from("channel send/receive declined by G5 v0 pairing (explicit FN)"),
                });
            }
            for r in rs {
                unsupported.push(UnsupportedFlow {
                    kind: UnsupportedFlowKind::Channel,
                    byte_range: r.byte_range.clone(),
                    note: Arc::from("channel send/receive declined by G5 v0 pairing (explicit FN)"),
                });
            }
            continue;
        }

        let send = ss[0];
        let recv = rs[0];
        let lhs = recv.lhs.as_ref().expect("checked above");
        transfers.push(ChannelTransfer {
            channel: Arc::clone(channel),
            send_value_text: Arc::clone(&send.value_text),
            recv_lhs: Arc::clone(lhs),
            recv_scope: recv.recv_scope,
            send_byte_range: send.byte_range.clone(),
            recv_byte_range: recv.byte_range.clone(),
        });
    }

    (transfers, unsupported)
}

/// Conservative: `ch := make(chan T, N)` in the same function scope → buffered → decline.
fn channel_looks_buffered(
    assignments: &[AssignmentDetail],
    channel: &str,
    function_scope: ScopeId,
) -> bool {
    for a in assignments {
        if a.lhs.as_ref() != channel {
            continue;
        }
        // Only consider decls nested under this function (scope id >= function
        // scope is not enough; use byte range via assignment being recorded
        // while that function was current — approximate: same or child scopes
        // by walking is hard here. Use: assignment scope's function field is
        // not on AssignmentDetail. Heuristic: any make(chan X, N) assigned to
        // this name anywhere in the unit with a comma before ')'.
        let rhs = a.rhs_text.as_ref().trim();
        if !rhs.starts_with("make(chan") {
            continue;
        }
        // Buffered if a top-level comma appears inside make(...).
        if let Some(open) = rhs.find('(') {
            let inner = &rhs[open + 1..];
            if let Some(close) = inner.rfind(')') {
                let args = &inner[..close];
                if args.contains(',') {
                    // Ignore function_scope mismatch: name collision across
                    // functions is rare; decline is the safe FN.
                    let _ = function_scope;
                    return true;
                }
            }
        }
    }
    false
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

#[cfg(test)]
mod pair_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn pairs_single_send_recv() {
        let sends = vec![ChannelSendSite {
            channel: Arc::from("ch"),
            value_text: Arc::from("x"),
            function_scope: 1,
            byte_range: 10..20,
            in_select: false,
        }];
        let recvs = vec![ChannelRecvSite {
            channel: Arc::from("ch"),
            lhs: Some(Arc::from("y")),
            function_scope: 1,
            recv_scope: 2,
            byte_range: 30..40,
            in_select: false,
        }];
        let (t, u) = pair_channel_transfers(&sends, &recvs, &[]);
        assert_eq!(t.len(), 1);
        assert!(u.is_empty());
        assert_eq!(t[0].recv_lhs.as_ref(), "y");
        assert_eq!(t[0].send_value_text.as_ref(), "x");
    }

    #[test]
    fn declines_multi_send() {
        let sends = vec![
            ChannelSendSite {
                channel: Arc::from("ch"),
                value_text: Arc::from("x"),
                function_scope: 1,
                byte_range: 10..20,
                in_select: false,
            },
            ChannelSendSite {
                channel: Arc::from("ch"),
                value_text: Arc::from("z"),
                function_scope: 1,
                byte_range: 21..30,
                in_select: false,
            },
        ];
        let recvs = vec![ChannelRecvSite {
            channel: Arc::from("ch"),
            lhs: Some(Arc::from("y")),
            function_scope: 1,
            recv_scope: 2,
            byte_range: 30..40,
            in_select: false,
        }];
        let (t, u) = pair_channel_transfers(&sends, &recvs, &[]);
        assert!(t.is_empty());
        assert_eq!(u.len(), 3);
    }
}

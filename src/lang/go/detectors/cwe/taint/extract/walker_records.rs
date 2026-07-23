use std::sync::Arc;

use super::super::{
    AssignmentDetail, ChannelRecvSite, ChannelSendSite, TaintSanitizerAnnotation,
    TaintSinkAnnotation, TaintSourceAnnotation,
};
use super::classify::{
    classify_sanitizer, classify_sink, classify_source, is_source_or_sanitizer_call,
};
use super::walker_core::{ExtractionState, is_chained_call};
use crate::lang::assignment::{extract_identifiers, split_assignment};

pub(super) fn record_call(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Some(func_text) = func.utf8_text(state.src_bytes).ok() else {
        return;
    };

    // Skip wrapper calls where the receiver is itself a call, e.g.
    // `r.URL.Query().Get("x")` — we classify the inner `r.URL.Query()` source.
    if is_chained_call(func) {
        return;
    }

    let byte_range = node.start_byte()..node.end_byte();

    if let Some(kind) = classify_source(func_text) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let result_var = result_variable_of_call(node, state.src_bytes);
        state.sources.push(TaintSourceAnnotation {
            function: Arc::from(func_text),
            kind,
            byte_range,
            result_variable: result_var.map(Arc::from),
            arguments: args.into_boxed_slice(),
        });
        return;
    }

    if let Some((kind, arg_index)) = classify_sink(func_text, node, state.src_bytes) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let arg_text = args.get(arg_index).cloned().unwrap_or_default();
        state.sinks.push(TaintSinkAnnotation {
            function: Arc::from(func_text),
            kind,
            argument_index: arg_index,
            argument_text: arg_text,
            all_arguments: args.into_boxed_slice(),
            byte_range,
        });
        return;
    }

    if let Some(kind) = classify_sanitizer(func_text) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let result_var = result_variable_of_call(node, state.src_bytes);
        state.sanitizers.push(TaintSanitizerAnnotation {
            function: Arc::from(func_text),
            kind,
            byte_range,
            result_variable: result_var.map(Arc::from),
            arguments: args.into_boxed_slice(),
        });
    }
}

pub(super) fn record_assignment(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let Some(text) = node.utf8_text(state.src_bytes).ok() else {
        return;
    };
    let Some((lhs, rhs)) = split_assignment(text) else {
        return;
    };
    let names = extract_identifiers(lhs);
    if names.is_empty() {
        return;
    }
    let scope = state.current_scope();
    let byte_range = node.start_byte()..node.end_byte();
    let from_call = is_source_or_sanitizer_call(rhs);
    let recv_channel = channel_from_receive_rhs(rhs);
    let lhs_name = names
        .first()
        .map(|n| normalize_lhs_key(n))
        .filter(|n| *n != "_");
    for name in &names {
        // Keep field-qualified keys (`user.Path`) as a single LHS name.
        let key = normalize_lhs_key(name);
        state.assignments.push(AssignmentDetail {
            lhs: Arc::from(key),
            rhs_text: Arc::from(rhs),
            scope,
            byte_range: byte_range.clone(),
            from_source_or_sanitizer: from_call,
            is_channel_send: false,
        });
    }

    // Staging: `y := <-ch` / `y = <-ch` (not select `receive_statement`).
    if let Some(channel) = recv_channel {
        state.channel_recvs.push(ChannelRecvSite {
            channel: Arc::from(channel),
            lhs: lhs_name.map(Arc::from),
            function_scope: state.current_function_scope(),
            recv_scope: scope,
            byte_range,
            in_select: is_inside_select(node),
        });
    }
}

/// Channel send staging — not an assignment edge. Pairing may promote to
/// [`super::super::ChannelTransfer`] or leave [`UnsupportedFlowKind::Channel`].
pub(super) fn record_send(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let byte_range = node.start_byte()..node.end_byte();
    let channel = node
        .child_by_field_name("channel")
        .and_then(|n| n.utf8_text(state.src_bytes).ok())
        .map(str::trim)
        .unwrap_or("");
    let value = node
        .child_by_field_name("value")
        .and_then(|n| n.utf8_text(state.src_bytes).ok())
        .map(str::trim)
        .unwrap_or("");
    if channel.is_empty() {
        return;
    }
    state.channel_sends.push(ChannelSendSite {
        channel: Arc::from(channel),
        value_text: Arc::from(value),
        function_scope: state.current_function_scope(),
        byte_range,
        in_select: is_inside_select(node),
    });
}

/// Goroutine launch is **not** modeled for taint (explicit FN).
pub(super) fn record_go_stmt(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let byte_range = node.start_byte()..node.end_byte();
    state.unsupported_flows.push(super::super::UnsupportedFlow {
        kind: super::super::UnsupportedFlowKind::Goroutine,
        byte_range,
        note: Arc::from("goroutine spawn is not tracked by taint (explicit FN)"),
    });
}

/// Select communication receive (`case y := <-ch:`) — always declined in G5 v0.
pub(super) fn record_select_receive(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    // receive_statement: optional left + right (unary <-ch).
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let Some(right_text) = right.utf8_text(state.src_bytes).ok() else {
        return;
    };
    let Some(channel) = channel_from_receive_rhs(right_text.trim()) else {
        return;
    };
    let lhs = node
        .child_by_field_name("left")
        .and_then(|n| n.utf8_text(state.src_bytes).ok())
        .map(str::trim)
        .and_then(|s| extract_identifiers(s).into_iter().next())
        .map(normalize_lhs_key)
        .filter(|n| *n != "_")
        .map(Arc::from);
    state.channel_recvs.push(ChannelRecvSite {
        channel: Arc::from(channel),
        lhs,
        function_scope: state.current_function_scope(),
        recv_scope: state.current_scope(),
        byte_range: node.start_byte()..node.end_byte(),
        in_select: true,
    });
}

/// Normalize assignment LHS: trim, keep `base.field` chains.
fn normalize_lhs_key(name: &str) -> &str {
    name.trim()
}

pub(super) fn is_inside_select(mut node: tree_sitter::Node) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "select_statement" {
            return true;
        }
        // Stop at function boundary — select outside this body is irrelevant.
        if matches!(
            parent.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

/// `<-ch` / `<- ch` → `Some("ch")` for simple identifier operands only.
fn channel_from_receive_rhs(rhs: &str) -> Option<&str> {
    let trimmed = rhs.trim();
    let rest = trimmed.strip_prefix("<-")?.trim();
    if rest.is_empty() {
        return None;
    }
    // Decline compound operands (`<-ch[i]`, `<-*p`, calls) in v0.
    if rest.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(rest)
    } else {
        None
    }
}

pub(crate) fn result_variable_at_return_index(lhs: &str, ret_idx: usize) -> Option<String> {
    let vars: Vec<&str> = lhs.split(',').map(str::trim).collect();
    let var = vars.get(ret_idx).or_else(|| vars.last())?;
    if !var.is_empty() && var.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(var.to_string())
    } else {
        None
    }
}

pub(super) fn result_variable_of_call<'a>(
    call: tree_sitter::Node,
    src: &'a [u8],
) -> Option<&'a str> {
    // Tree-sitter Go: a short_var_declaration or assignment_statement whose
    // right child is the call_expression. We climb to the parent statement.
    let mut parent = call.parent()?;
    while !matches!(
        parent.kind(),
        "assignment_statement" | "short_var_declaration" | "send_statement"
    ) {
        parent = parent.parent()?;
    }
    // IP-010 residual quarantine (G5): a source used as a send value must NOT
    // attribute the channel identifier as the result variable. That quirk was
    // non-contractual "channel support." Channel flow goes through
    // ChannelTransfer only when pairing rules hold.
    if parent.kind() == "send_statement" {
        return None;
    }
    let left = parent.child_by_field_name("left")?;
    left.utf8_text(src).ok().map(str::trim)
}

pub(super) fn argument_texts<'a>(call: tree_sitter::Node, src: &'a [u8]) -> Vec<&'a str> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter_map(|n| n.utf8_text(src).ok().map(str::trim))
        .collect()
}

#[cfg(test)]
mod channel_rhs_tests {
    use super::channel_from_receive_rhs;

    #[test]
    fn parses_simple_receive_rhs() {
        assert_eq!(channel_from_receive_rhs("<-ch"), Some("ch"));
        assert_eq!(channel_from_receive_rhs(" <- ch "), Some("ch"));
        assert_eq!(channel_from_receive_rhs("<-ch[0]"), None);
        assert_eq!(channel_from_receive_rhs("x"), None);
    }
}

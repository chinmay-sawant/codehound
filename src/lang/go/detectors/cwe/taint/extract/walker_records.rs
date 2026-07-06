use std::sync::Arc;

use super::super::{
    AssignmentDetail, TaintSanitizerAnnotation, TaintSinkAnnotation, TaintSourceAnnotation,
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
    for name in names {
        state.assignments.push(AssignmentDetail {
            lhs: Arc::from(name),
            rhs_text: Arc::from(rhs),
            scope,
            byte_range: byte_range.clone(),
            from_source_or_sanitizer: from_call,
        });
    }
}

pub(super) fn record_send(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let Some(channel) = node.child_by_field_name("channel") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let ch_text = match channel.utf8_text(state.src_bytes) {
        Ok(t) => t.trim(),
        Err(_) => return,
    };
    let val_text = match value.utf8_text(state.src_bytes) {
        Ok(t) => t,
        Err(_) => return,
    };
    let scope = state.current_scope();
    let byte_range = node.start_byte()..node.end_byte();
    let from_call = is_source_or_sanitizer_call(val_text);
    state.assignments.push(AssignmentDetail {
        lhs: Arc::from(ch_text),
        rhs_text: Arc::from(val_text),
        scope,
        byte_range,
        from_source_or_sanitizer: from_call,
    });
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
    if parent.kind() == "send_statement" {
        return parent
            .child_by_field_name("channel")
            .and_then(|n| n.utf8_text(src).ok().map(str::trim));
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

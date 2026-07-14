//! Phase 4 concurrency candidates with deliberately local proof obligations.
//!
//! The coordinator owns registration, metadata, manifests, and documentation.
//! These detectors therefore stay self-contained and only rely on syntax that
//! can be established inside one function. They do not attempt ownership,
//! race, or interprocedural control-flow analysis.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-86: a mutex is locked in a function without any matching unlock.
///
/// This intentionally reports only the strongest case: the same receiver has
/// no visible `Unlock` at all. Branch-sensitive "all paths" reasoning is out
/// of scope for a syntax-only detector.
pub(crate) fn detect_bp_86_mutex_lock_without_unlock(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(function_text) = function.utf8_text(source) else {
                return;
            };
            if !has_sync_mutex_evidence(function_text) {
                return;
            }

            let mut locks = Vec::new();
            let mut unlocks = Vec::new();
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" {
                    return;
                }
                let Some((receiver, method)) = receiver_method(node, source) else {
                    return;
                };
                match method {
                    "Lock" => locks.push((receiver.to_owned(), node.start_byte())),
                    "Unlock" => unlocks.push(receiver.to_owned()),
                    _ => {}
                }
            });

            for (receiver, byte) in locks {
                if is_declared_mutex_receiver(function_text, &receiver)
                    && !unlocks.iter().any(|unlock| unlock == &receiver)
                {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_86_META,
                        byte,
                        "mutex is locked without a visible matching Unlock in this function",
                    );
                }
            }
        },
    );
}

/// BP-87: a read lock remains held while the function performs an obvious
/// blocking operation. The detector requires an explicit sync.RWMutex and a
/// visible matching RUnlock before reporting the local source interval.
pub(crate) fn detect_bp_87_rlock_across_blocking_call(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(function_text) = function.utf8_text(source) else {
                return;
            };
            if !has_sync_rwmutex_evidence(function_text) {
                return;
            }

            let mut events = Vec::new();
            walk_scope(body, body, source, &mut |node| {
                if node.kind() == "call_expression" {
                    if let Some((receiver, method)) = receiver_method(node, source) {
                        events.push(Event::Call {
                            receiver: receiver.to_owned(),
                            method: method.to_owned(),
                            byte: node.start_byte(),
                        });
                    }
                } else if is_receive(node, source) {
                    events.push(Event::Receive);
                }
            });

            for (index, event) in events.iter().enumerate() {
                let Event::Call {
                    receiver,
                    method,
                    byte,
                } = event
                else {
                    continue;
                };
                if method != "RLock" {
                    continue;
                }
                if !is_declared_rwmutex_receiver(function_text, receiver) {
                    continue;
                }

                let mut blocked = false;
                let mut unlocked = false;
                for next in events.iter().skip(index + 1) {
                    match next {
                        Event::Call {
                            receiver: next_receiver,
                            method: next_method,
                            ..
                        } if next_receiver == receiver && next_method == "RUnlock" => {
                            unlocked = true;
                            break;
                        }
                        Event::Call { method, .. } if is_blocking_method(method) => blocked = true,
                        Event::Receive => blocked = true,
                        _ => {}
                    }
                }

                if blocked && unlocked {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_87_META,
                        *byte,
                        "RLock is held across a blocking operation; copy protected state before waiting",
                    );
                }
            }
        },
    );
}

/// BP-89: the same channel is closed twice by unconditional statements in a
/// single function. Conditional or loop-contained closes are deliberately
/// deferred because proving ownership and reachability needs control-flow
/// analysis.
pub(crate) fn detect_bp_89_repeated_channel_close(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let mut closes: Vec<(String, usize)> = Vec::new();
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" || !is_builtin_close(node, source) {
                    return;
                }
                if !is_unconditional(node, function) {
                    return;
                }
                let Some(argument) = node
                    .child_by_field_name("arguments")
                    .and_then(|arguments| arguments.named_child(0))
                    .and_then(|argument| argument.utf8_text(source).ok())
                    .and_then(simple_identifier)
                else {
                    return;
                };
                closes.push((argument.to_owned(), node.start_byte()));
            });

            for (index, (channel, byte)) in closes.iter().enumerate() {
                if closes
                    .iter()
                    .take(index)
                    .any(|(previous, _)| previous == channel)
                {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_89_META,
                        *byte,
                        "channel is closed more than once by unconditional statements in this function",
                    );
                    break;
                }
            }
        },
    );
}

#[derive(Debug)]
enum Event {
    Call {
        receiver: String,
        method: String,
        byte: usize,
    },
    Receive,
}

fn inspect_functions(root: Node, source: &[u8], mut inspect: impl FnMut(Node, &[u8])) {
    fn walk(node: Node, source: &[u8], inspect: &mut impl FnMut(Node, &[u8])) {
        if is_function_like(node.kind()) {
            inspect(node, source);
            return;
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, source, inspect);
        }
    }

    walk(root, source, &mut inspect);
}

fn walk_scope(node: Node, scope: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if node.id() != scope.id() && is_function_like(node.kind()) {
        return;
    }
    visit(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_scope(child, scope, source, visit);
    }
    let _ = source;
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn receiver_method<'a>(node: Node<'a>, source: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let callee = node
        .child_by_field_name("function")?
        .utf8_text(source)
        .ok()?;
    let (receiver, method) = callee.rsplit_once('.')?;
    simple_identifier(receiver).zip(simple_identifier(method))
}

fn has_sync_mutex_evidence(function_text: &str) -> bool {
    function_text.contains("sync.Mutex") || function_text.contains("sync.RWMutex")
}

fn has_sync_rwmutex_evidence(function_text: &str) -> bool {
    function_text.contains("sync.RWMutex")
}

fn is_declared_mutex_receiver(function_text: &str, receiver: &str) -> bool {
    [
        format!("var {receiver} sync.Mutex"),
        format!("var {receiver} sync.RWMutex"),
        format!("{receiver} *sync.Mutex"),
        format!("{receiver} *sync.RWMutex"),
    ]
    .iter()
    .any(|pattern| function_text.contains(pattern))
}

fn is_declared_rwmutex_receiver(function_text: &str, receiver: &str) -> bool {
    [
        format!("var {receiver} sync.RWMutex"),
        format!("{receiver} *sync.RWMutex"),
    ]
    .iter()
    .any(|pattern| function_text.contains(pattern))
}

fn is_blocking_method(method: &str) -> bool {
    matches!(method, "Do" | "Exec" | "Query" | "Read" | "Sleep")
}

fn is_receive(node: Node, source: &[u8]) -> bool {
    if node.kind() == "receive_expression" {
        return true;
    }
    node.kind() == "unary_expression"
        && node
            .utf8_text(source)
            .is_ok_and(|text| text.trim_start().starts_with("<-"))
}

fn is_builtin_close(node: Node, source: &[u8]) -> bool {
    node.child_by_field_name("function")
        .and_then(|function| function.utf8_text(source).ok())
        == Some("close")
}

fn is_unconditional(mut node: Node, function: Node) -> bool {
    while let Some(parent) = node.parent() {
        if parent.id() == function.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "for_statement"
                | "range_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
                | "select_statement"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn simple_identifier(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_'))
    .then_some(value)
}

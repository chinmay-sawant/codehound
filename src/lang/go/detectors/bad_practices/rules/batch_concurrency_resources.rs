//! Batch B — narrow concurrency and resource-lifecycle rules (BP-88, BP-98, BP-99).
//!
//! These detectors intentionally stop at same-function source facts. They do not
//! attempt race detection, ownership inference, or interprocedural control-flow.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-88: a local zero-value channel is used directly for send or receive.
///
/// The deliberately narrow form only handles `var ch chan T` declarations and
/// direct operations outside a `select`. An intentional nil-channel select is
/// therefore not reported, and any visible `ch = make(chan T)` suppresses the
/// finding.
pub(crate) fn detect_bp_88_nil_channel_operation(
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
            let declarations = collect_nil_channel_declarations(body, source);
            if declarations.is_empty() {
                return;
            }

            walk_scope(body, body, source, &mut |node| {
                let operation = match node.kind() {
                    "send_statement" => direct_send_channel(node, source),
                    "unary_expression" | "receive_expression" => {
                        direct_receive_channel(node, source)
                    }
                    _ => None,
                };
                let Some(channel) = operation else {
                    return;
                };
                if inside_select(node) {
                    return;
                }

                let Some((_, declaration_end)) =
                    declarations.iter().find(|(name, declaration_end)| {
                        *name == channel && *declaration_end < node.start_byte()
                    })
                else {
                    return;
                };
                if channel_initialized_with_make(
                    source,
                    body.start_byte(),
                    *declaration_end,
                    node.start_byte(),
                    &channel,
                ) {
                    return;
                }

                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_88_META,
                    node.start_byte(),
                    "channel is used before make; a nil channel send or receive blocks forever",
                );
            });
        },
    );
}

/// BP-98: a local `os.Open`/`os.OpenFile` result is neither closed nor returned.
///
/// This is intentionally stricter than the plan's general error-path wording:
/// a result transferred to the caller is exempt, while an owned result with no
/// same-function close is reported. That avoids claiming interprocedural
/// ownership and avoids duplicating HTTP/SQL-specific lifecycle checks.
pub(crate) fn detect_bp_98_open_file_without_close(
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
            let body_text = body.utf8_text(source).unwrap_or_default();

            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" || !is_file_open_call(node, source) {
                    return;
                }
                let Some(file_name) = assigned_identifier(node, source) else {
                    return;
                };
                if has_close_or_transfer(body_text, &file_name) {
                    return;
                }

                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_98_META,
                    node.start_byte(),
                    "opened file is neither closed nor transferred to the caller",
                );
            });
        },
    );
}

/// BP-99: `sync.Cond.Wait` is reached in a function with no visible locker use.
///
/// `Cond.Wait` requires its associated Locker to be held. We only report the
/// high-confidence case where the condition is locally created and the owning
/// function contains no `Lock` call at all. If locking may happen in a helper or
/// in control flow this detector stays silent rather than pretending to prove it.
pub(crate) fn detect_bp_99_cond_wait_without_lock(
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
            let body_text = body.utf8_text(source).unwrap_or_default();
            let mut conditions = Vec::new();

            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" || !is_new_cond_call(node, source) {
                    return;
                }
                let Some(condition_name) = assigned_identifier(node, source) else {
                    return;
                };
                let Some(lock_name) = cond_lock_name(node, source) else {
                    return;
                };
                conditions.push((condition_name, lock_name));
            });

            if conditions.is_empty() {
                return;
            }

            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" {
                    return;
                }
                let Some(callee) = node
                    .child_by_field_name("function")
                    .and_then(|child| child.utf8_text(source).ok())
                else {
                    return;
                };
                let Some((_, lock_name)) = conditions
                    .iter()
                    .find(|(condition_name, _)| callee == format!("{condition_name}.Wait"))
                else {
                    return;
                };
                if body_text.contains(&format!("{lock_name}.Lock()"))
                    || body_text.contains(&format!("{lock_name}.RLock()"))
                {
                    return;
                }

                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_99_META,
                    node.start_byte(),
                    "sync.Cond.Wait has no visible Lock/RLock acquisition for its associated locker",
                );
            });
        },
    );
}

fn inspect_functions(root: Node, source: &[u8], mut inspect: impl FnMut(Node, &[u8])) {
    fn walk(node: Node, source: &[u8], inspect: &mut impl FnMut(Node, &[u8])) {
        if is_function(node) {
            inspect(node, source);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, source, inspect);
        }
    }

    walk(root, source, &mut inspect);
}

fn walk_scope(node: Node, scope: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if node.id() != scope.id() && is_function(node) {
        return;
    }
    visit(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_scope(child, scope, source, visit);
    }
    let _ = source;
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn collect_nil_channel_declarations(body: Node, source: &[u8]) -> Vec<(String, usize)> {
    let mut declarations = Vec::new();
    walk_scope(body, body, source, &mut |node| {
        if node.kind() != "var_declaration" {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let Some(name) = nil_channel_name(text) else {
            return;
        };
        declarations.push((name, node.end_byte()));
    });
    declarations
}

fn nil_channel_name(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("var ")?;
    let mut parts = rest.split_whitespace();
    let name = parts.next()?;
    let declaration = parts.collect::<Vec<_>>().join(" ");
    if name.contains(',') || !declaration.contains("chan") || declaration.contains("=") {
        return None;
    }
    Some(name.to_owned())
}

fn direct_send_channel(node: Node, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?.trim();
    let (channel, _) = text.split_once("<-")?;
    simple_identifier(channel.trim()).map(str::to_owned)
}

fn direct_receive_channel(node: Node, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?.trim();
    let channel = text.strip_prefix("<-")?.trim();
    simple_identifier(channel).map(str::to_owned)
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

fn inside_select(mut node: Node) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "select_statement" | "select_clause") {
            return true;
        }
        node = parent;
    }
    false
}

fn channel_initialized_with_make(
    source: &[u8],
    body_start: usize,
    declaration_end: usize,
    operation_start: usize,
    name: &str,
) -> bool {
    let start = declaration_end.saturating_sub(body_start);
    let end = operation_start.saturating_sub(body_start);
    let Ok(body) = std::str::from_utf8(&source[body_start..]) else {
        return false;
    };
    let region = body.get(start..end).unwrap_or_default();
    region.lines().any(|line| {
        let trimmed = line.trim_start();
        (trimmed.starts_with(&format!("{name} =")) || trimmed.starts_with(&format!("{name} :=")))
            && trimmed.contains("make(chan")
    })
}

fn is_file_open_call(node: Node, source: &[u8]) -> bool {
    node.child_by_field_name("function")
        .and_then(|child| child.utf8_text(source).ok())
        .is_some_and(|callee| matches!(callee, "os.Open" | "os.OpenFile"))
}

fn is_new_cond_call(node: Node, source: &[u8]) -> bool {
    node.child_by_field_name("function")
        .and_then(|child| child.utf8_text(source).ok())
        == Some("sync.NewCond")
}

fn assigned_identifier(node: Node, source: &[u8]) -> Option<String> {
    let mut current = node.parent();
    for _ in 0..4 {
        let parent = current?;
        if matches!(
            parent.kind(),
            "short_var_declaration" | "assignment_statement"
        ) {
            let text = parent.utf8_text(source).ok()?;
            let lhs = text
                .split_once(":=")
                .or_else(|| text.split_once('='))?
                .0
                .trim();
            let name = lhs.split(',').next()?.trim();
            return simple_identifier(name).map(str::to_owned);
        }
        current = parent.parent();
    }
    None
}

fn has_close_or_transfer(body: &str, name: &str) -> bool {
    let close = format!("{name}.Close(");
    body.contains(&close)
        || body.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("return ")
                && trimmed
                    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                    .any(|token| token == name)
        })
}

fn cond_lock_name(node: Node, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let argument = text.get(open + 1..close)?.trim();
    simple_identifier(argument.strip_prefix('&').unwrap_or(argument).trim()).map(str::to_owned)
}

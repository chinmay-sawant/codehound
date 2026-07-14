//! Batch A deferred core-language checks.
//!
//! These rules intentionally use only local syntax facts. They do not infer
//! application-wide logging policy, timezone policy, or synchronization
//! ownership; the coordinator promotes them only after registering metadata
//! and dispatch entries.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-70: an error branch logs the error and then falls through to the next
/// statement. Only error-shaped log calls that mention the checked variable
/// are considered; informational `log.Printf` calls remain out of scope.
pub(crate) fn detect_bp_70_logging_error_then_continuing(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_bp_70(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_70(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "if_statement"
        && let Some(condition) = node.child_by_field_name("condition")
        && let Some(error_name) = error_name_from_condition(condition, source)
        && let Some(consequence) = node.child_by_field_name("consequence")
        && !contains_explicit_exit(consequence, source)
        && contains_error_log(consequence, source, error_name)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_70_META,
            condition.start_byte(),
            "error is logged and execution continues; return, panic, or otherwise handle the failure",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_70(child, source, unit, out);
    }
}

fn error_name_from_condition<'a>(condition: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    let text = condition.utf8_text(source).ok()?.trim();
    let (left, right) = text.split_once("!=")?;
    if right.trim() != "nil" {
        return None;
    }

    let candidate = left.trim();
    is_identifier(candidate).then_some(candidate)
}

fn contains_explicit_exit(node: Node, source: &[u8]) -> bool {
    if matches!(
        node.kind(),
        "return_statement" | "break_statement" | "continue_statement"
    ) {
        return true;
    }

    if node.kind() == "call_expression"
        && let Some(name) = call_name(node, source)
        && (matches!(
            name,
            "panic" | "os.Exit" | "log.Fatal" | "log.Fatalf" | "log.Fatalln" | "runtime.Goexit"
        ) || name.ends_with(".Fatal")
            || name.ends_with(".Fatalf")
            || name.ends_with(".Fatalln"))
    {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| !is_function(child) && contains_explicit_exit(child, source))
}

fn contains_error_log(node: Node, source: &[u8], error_name: &str) -> bool {
    if node.kind() == "call_expression"
        && is_error_log_call(node, source)
        && call_mentions_identifier(node, source, error_name)
    {
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| !is_function(child) && contains_error_log(child, source, error_name))
}

fn is_error_log_call(node: Node, source: &[u8]) -> bool {
    let Some(name) = call_name(node, source) else {
        return false;
    };
    if !matches!(name, "log.Print" | "log.Printf" | "log.Println") {
        return false;
    }

    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    let Some(message) = arguments.named_children(&mut cursor).next() else {
        return false;
    };
    let Ok(message) = message.utf8_text(source) else {
        return false;
    };
    error_message_literal(message)
}

fn error_message_literal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "error",
        "failed",
        "failure",
        "unable",
        "cannot",
        "could not",
        "invalid",
        "timeout",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn call_mentions_identifier(node: Node, source: &[u8], name: &str) -> bool {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|argument| {
        !matches!(
            argument.kind(),
            "interpreted_string_literal" | "raw_string_literal"
        ) && argument
            .utf8_text(source)
            .is_ok_and(|text| contains_identifier(text, name))
    })
}

/// BP-82: `time.Parse` with a literal layout that contains no zone directive
/// silently constructs a UTC value. Dynamic layouts are left alone because
/// this source-only detector cannot prove their timezone semantics.
pub(crate) fn detect_bp_82_time_parse_without_location(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_bp_82(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_82(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression"
        && call_name(node, source) == Some("time.Parse")
        && let Some(arguments) = node.child_by_field_name("arguments")
        && let Some(layout) = first_named_child(arguments)
        && layout
            .utf8_text(source)
            .is_ok_and(literal_layout_without_zone)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_82_META,
            node.start_byte(),
            "time.Parse uses a layout without timezone information; use ParseInLocation or an explicit UTC/RFC layout",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_82(child, source, unit, out);
    }
}

fn literal_layout_without_zone(text: &str) -> bool {
    let text = text.trim();
    let literal = text
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            text.strip_prefix('`')
                .and_then(|value| value.strip_suffix('`'))
        });
    let Some(layout) = literal else {
        return false;
    };

    if layout.is_empty() {
        return false;
    }

    let has_zone = layout.contains("MST")
        || layout.contains("-07")
        || layout.contains("Z07")
        || layout.ends_with('Z');
    !has_zone
}

/// BP-83: a synchronization-shaped function or launched goroutine sleeps
/// without a visible channel, lock, wait, or atomic boundary. Backoff and
/// retry code is deliberately excluded because its delay is the behavior.
pub(crate) fn detect_bp_83_sleep_for_synchronization(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_bp_83(unit.tree.root_node(), unit.source.as_bytes(), unit, out);
}

fn walk_bp_83(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression"
        && call_name(node, source) == Some("time.Sleep")
        && let Some(function) = enclosing_function(node)
        && is_sync_shape(function, source)
        && !contains_visible_synchronization(function, source)
        && !is_backoff_or_retry(function, source)
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_83_META,
            node.start_byte(),
            "time.Sleep is being used as synchronization without a visible coordination primitive",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_bp_83(child, source, unit, out);
    }
}

fn enclosing_function<'a>(mut node: Node<'a>) -> Option<Node<'a>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn is_sync_shape(function: Node, source: &[u8]) -> bool {
    let name = function
        .child_by_field_name("name")
        .and_then(|name| name.utf8_text(source).ok())
        .unwrap_or_default()
        .to_ascii_lowercase();

    [
        "wait", "ready", "sync", "until", "drain", "flush", "shutdown", "startup", "start", "stop",
        "signal", "notify", "done",
    ]
    .iter()
    .any(|needle| name.contains(needle))
        || is_go_launched(function)
}

fn is_go_launched(function: Node) -> bool {
    let mut current = function.parent();
    while let Some(node) = current {
        if node.kind() == "go_statement" {
            return true;
        }
        if matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return false;
        }
        current = node.parent();
    }
    false
}

fn contains_visible_synchronization(function: Node, source: &[u8]) -> bool {
    let text = function.utf8_text(source).unwrap_or_default();
    [
        "<-", "select", ".Wait(", ".Lock(", ".Unlock(", "sync.", "atomic.", "Cond", "Once",
        "close(",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn is_backoff_or_retry(function: Node, source: &[u8]) -> bool {
    let text = function
        .utf8_text(source)
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        "backoff",
        "retry",
        "throttle",
        "rate_limit",
        "ratelimit",
        "jitter",
        "cooldown",
        "debounce",
        "poll",
        "periodic",
        "interval",
        "timeout",
        "delay",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn first_named_child<'a>(node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn contains_identifier(text: &str, name: &str) -> bool {
    text.split(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .any(|part| part == name)
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        contains_identifier, error_message_literal, is_identifier, literal_layout_without_zone,
    };

    #[test]
    fn bp70_only_accepts_error_shaped_log_messages() {
        assert!(error_message_literal("load failed: %v"));
        assert!(error_message_literal("invalid response"));
        assert!(!error_message_literal("request received"));
    }

    #[test]
    fn bp70_identifier_matching_does_not_match_a_longer_name() {
        assert!(contains_identifier("fmt.Printf(\"%v\", err)", "err"));
        assert!(!contains_identifier("fmt.Printf(\"%v\", error)", "err"));
    }

    #[test]
    fn bp82_requires_a_literal_layout_without_zone_information() {
        assert!(literal_layout_without_zone("\"2006-01-02 15:04:05\""));
        assert!(!literal_layout_without_zone(
            "\"2006-01-02T15:04:05Z07:00\""
        ));
        assert!(!literal_layout_without_zone("time.RFC3339"));
    }

    #[test]
    fn identifier_helper_is_exact() {
        assert!(is_identifier("err"));
        assert!(is_identifier("loadErr2"));
        assert!(!is_identifier("err != nil"));
    }
}

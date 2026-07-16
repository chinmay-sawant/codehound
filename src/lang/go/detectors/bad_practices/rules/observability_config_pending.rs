//! High-signal observability and JSON-boundary checks from Part E.
//!
//! These checks intentionally stay inside one parsed Go file. They do not
//! infer deployment policy, configuration criticality, or package-wide
//! lifecycle contracts.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-146: a logger receives a sensitive field or value without an obvious
/// redaction step.
pub(crate) fn detect_bp_146_sensitive_fields_logged(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    let has_log = has_import(root, source, "log");
    let has_slog = has_import(root, source, "log/slog");
    let has_zap = has_import(root, source, "go.uber.org/zap");
    if !(has_log || has_slog || has_zap) {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        if !is_logger_call(name, has_log, has_slog, has_zap) {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        if contains_sensitive_value(text) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_146_META,
                node.start_byte(),
                "sensitive logging field or value is passed without an obvious redaction",
            );
        }
    });
}

/// BP-147: a non-main package mixes the standard logger with a structured
/// logger. `log.Print*` is deliberately the only stdlib shape admitted.
pub(crate) fn detect_bp_147_unstructured_service_logging(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    if package_name(unit.source.as_ref()) == Some("main") || !has_import(root, source, "log") {
        return;
    }
    let has_structured =
        has_import(root, source, "log/slog") || has_import(root, source, "go.uber.org/zap");
    if !has_structured {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        if matches!(name, "log.Print" | "log.Printf" | "log.Println") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_147_META,
                node.start_byte(),
                "service package mixes log.Print* with a structured logger",
            );
        }
    });
}

/// BP-149: an error-level logger call inside an `err != nil` branch omits the
/// error value itself. The branch check keeps ordinary informational errors
/// and unrelated logging outside the rule.
pub(crate) fn detect_bp_149_error_log_without_attribute(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    let has_slog = has_import(root, source, "log/slog");
    let has_zap = has_import(root, source, "go.uber.org/zap");
    if !(has_slog || has_zap) {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        if !is_error_logger_call(name, has_slog, has_zap) {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        if contains_identifier(text, "err") || contains_identifier(text, "error") {
            return;
        }
        if has_error_guard_ancestor(node, source) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_149_META,
                node.start_byte(),
                "error-level log in an error branch omits the error attribute",
            );
        }
    });
}

/// BP-155: a JSON decoder reads an HTTP request body without a visible
/// `http.MaxBytesReader` in the containing function.
pub(crate) fn detect_bp_155_unbounded_json_request_body(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    if !has_import(root, source, "encoding/json") || !has_import(root, source, "net/http") {
        return;
    }

    walk_nodes(root, &mut |function| {
        if !matches!(
            function.kind(),
            "function_declaration" | "method_declaration"
        ) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let Ok(body_text) = body.utf8_text(source) else {
            return;
        };
        if body_text.contains("http.MaxBytesReader(") {
            return;
        }
        let Some(decoder) = find_unbounded_body_decoder(body, source) else {
            return;
        };
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_155_META,
            decoder,
            "JSON request body is decoded without an http.MaxBytesReader limit",
        );
    });
}

/// BP-156: a security-sensitive JSON field uses `omitempty`, making a zero
/// value disappear from the wire representation.
pub(crate) fn detect_bp_156_sensitive_json_omitempty(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();

    walk_nodes(root, &mut |node| {
        if node.kind() != "field_declaration" {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let lower = text.to_ascii_lowercase();
        if lower.contains("omitempty") && lower.contains("json:") && contains_sensitive_name(&lower)
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_156_META,
                node.start_byte(),
                "security-sensitive JSON field uses omitempty; encode its zero value explicitly",
            );
        }
    });
}

fn is_logger_call(name: &str, has_log: bool, has_slog: bool, has_zap: bool) -> bool {
    (has_log && matches!(name, "log.Print" | "log.Printf" | "log.Println"))
        || (has_slog
            && matches!(
                name,
                "slog.Debug"
                    | "slog.Info"
                    | "slog.Warn"
                    | "slog.Error"
                    | "slog.Log"
                    | "slog.LogAttrs"
            ))
        || (has_zap && is_zap_level(name))
}

fn is_error_logger_call(name: &str, has_slog: bool, has_zap: bool) -> bool {
    (has_slog && name == "slog.Error") || (has_zap && is_zap_error(name))
}

fn is_zap_level(name: &str) -> bool {
    (name.starts_with("zap.L().") || name.starts_with("zap.S()."))
        && matches!(
            name.rsplit('.').next(),
            Some("Debug" | "Info" | "Warn" | "Error" | "DPanic" | "Panic" | "Fatal")
        )
}

fn is_zap_error(name: &str) -> bool {
    (name.starts_with("zap.L().") || name.starts_with("zap.S().")) && name.ends_with(".Error")
}

fn contains_sensitive_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if ["redact", "redacted", "mask", "masked", "hash"]
        .iter()
        .any(|word| contains_identifier(&lower, word))
    {
        return false;
    }

    let has_sensitive = contains_sensitive_name(&lower);
    let has_format_value = ["%s", "%v", "%q", "%x", "%d"]
        .iter()
        .any(|verb| lower.contains(verb));
    // A boolean presence check such as `token != ""` is safe to log; `%t`
    // does not serialize the credential itself.
    if !has_format_value && lower.contains("%t") {
        return false;
    }
    has_sensitive
        && (has_format_value
            || [
                "password",
                "passwd",
                "secret",
                "token",
                "authorization",
                "api_key",
                "private_key",
                "client_secret",
            ]
            .iter()
            .any(|name| lower.matches(name).count() >= 2))
}

fn contains_sensitive_name(text: &str) -> bool {
    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "api_key",
        "private_key",
        "client_secret",
    ]
    .iter()
    .any(|name| text.contains(name))
}

fn has_error_guard_ancestor(node: Node, source: &[u8]) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "if_statement"
            && parent
                .child_by_field_name("condition")
                .and_then(|condition| condition.utf8_text(source).ok())
                .is_some_and(is_non_nil_error_check)
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn is_non_nil_error_check(condition: &str) -> bool {
    let normalized: String = condition
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (normalized.contains("err!=nil") || normalized.contains("error!=nil"))
        && !normalized.contains("nil!=err")
        && !normalized.contains("nil!=error")
}

fn find_unbounded_body_decoder(root: Node, source: &[u8]) -> Option<usize> {
    let mut found = None;
    walk_nodes(root, &mut |node| {
        if found.is_some() || node.kind() != "call_expression" {
            return;
        }
        let Some(name) = call_name(node, source) else {
            return;
        };
        if !name.ends_with(".Decode") || !name.contains("json.NewDecoder(") {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        if text.contains(".Body") {
            found = Some(node.start_byte());
        }
    });
    found
}

fn package_name(source: &str) -> Option<&str> {
    source.lines().find_map(|line| {
        line.trim()
            .strip_prefix("package ")
            .map(str::trim)
            .filter(|name| !name.is_empty())
    })
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    let needle = format!("\"{path}\"");
    let mut found = false;
    walk_nodes(root, &mut |node| {
        if !found
            && matches!(node.kind(), "import_spec" | "import_declaration")
            && node
                .utf8_text(source)
                .is_ok_and(|text| text.contains(&needle))
        {
            found = true;
        }
    });
    found
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn contains_identifier(text: &str, wanted: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|identifier| identifier == wanted)
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
    }
}

//! Batch D — conservative observability/configuration checks.
//!
//! This module only admits patterns that are directly visible in one parsed Go
//! file. It deliberately does not infer whether a configuration value is
//! required or whether a logger is a startup logger. Registration, metadata,
//! and fixture-manifest changes belong to the central integration pass.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-151: a sensitive environment value is passed directly to a logger.
///
/// The direct-call restriction keeps this rule useful without pretending to
/// have whole-program taint or alias analysis. Values copied through local
/// variables are intentionally left for a future dataflow-aware detector.
pub(crate) fn detect_bp_151_secret_env_logged(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !unit.source.contains("Getenv")
        || !(index.has("log.") || unit.source.contains("slog.") || unit.source.contains("zap."))
    {
        return;
    }
    let root = unit.tree.root_node();
    let source = unit.source.as_bytes();
    let has_log = has_import(root, source, "log");
    let has_slog = has_import(root, source, "log/slog");
    let has_zap = has_import(root, source, "go.uber.org/zap");
    if !has_import(root, source, "os") || !(has_log || has_slog || has_zap) {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression"
            || !is_logger_call(node, source, has_log, has_slog, has_zap)
        {
            return;
        }

        let Some(secret_env_start) = find_sensitive_getenv(node, source) else {
            return;
        };
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_151_META,
            secret_env_start,
            "secret environment value is passed directly to a logger; redact or log only presence",
        );
    });
}

fn is_logger_call(node: Node, source: &[u8], has_log: bool, has_slog: bool, has_zap: bool) -> bool {
    let Some(name) = call_name(node, source) else {
        return false;
    };

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
        || (has_zap && is_zap_logger_method(name))
}

fn is_zap_logger_method(name: &str) -> bool {
    if !(name.starts_with("zap.L().") || name.starts_with("zap.S().")) {
        return false;
    }
    matches!(
        name.rsplit('.').next(),
        Some("Debug" | "Info" | "Warn" | "Error" | "DPanic" | "Panic" | "Fatal")
    )
}

fn find_sensitive_getenv(node: Node, source: &[u8]) -> Option<usize> {
    let mut found = None;
    walk_nodes(node, &mut |candidate| {
        if found.is_some() || candidate.kind() != "call_expression" {
            return;
        }
        if call_name(candidate, source) != Some("os.Getenv") {
            return;
        }
        let Some(arguments) = candidate.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        let Some(argument) = arguments.named_children(&mut cursor).next() else {
            return;
        };
        let Ok(name) = argument.utf8_text(source) else {
            return;
        };
        if is_sensitive_name(name) {
            found = Some(candidate.start_byte());
        }
    });
    found
}

fn is_sensitive_name(text: &str) -> bool {
    let name = text
        .trim()
        .trim_matches('"')
        .trim_matches('`')
        .to_ascii_uppercase();
    [
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "API_KEY",
        "PRIVATE_KEY",
        "AUTHORIZATION",
        "CLIENT_SECRET",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
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

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    fn walk(node: Node, visit: &mut impl FnMut(Node)) {
        visit(node);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, visit);
        }
    }
    walk(root, visit);
}

use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::{GoPerfFacts, VarKind};
use super::super::super::super::metadata::*;
use crate::ast::nearest_loop;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

/// PERF-28: `sync.Mutex` / `sync.RWMutex` declared per request or per record.
pub(crate) fn detect_perf_28(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
        return;
    }
    if !facts.source_index.has("sync.Mutex") && !facts.source_index.has("sync.RWMutex") {
        return;
    }
    // A package-scope singleton mutex is fine.
    if facts.source_index.has(
        "var mu sync.Mutex
",
    ) || facts.source_index.has("var mu sync.Mutex =")
        || facts.source_index.has(
            "var (
",
        )
        || facts.source_index.has(
            "var rwMu sync.RWMutex
",
        )
    {
        return;
    }
    // Mutex embedded inside a struct that is itself constructed per request
    // — the "per-record" pattern. We can only detect this from source
    // strings; the `sync.Mutex` token must appear inside a `type … struct`
    // block and that struct must be instantiated in the handler.
    let in_struct = facts.source_index.has("struct {")
        && (facts.source_index.has("	mu sync.Mutex")
            || facts.source_index.has(
                "mu sync.Mutex
",
            )
            || facts.source_index.has("rwMu sync.RWMutex"));
    let literal_in_handler =
        facts.source_index.has("sync.Mutex{") || facts.source_index.has("sync.RWMutex{");
    if !in_struct && !literal_in_handler {
        return;
    }

    let start = source
        .find("sync.Mutex")
        .or_else(|| source.find("sync.RWMutex"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_28,
        file,
        line,
        col,
        "sync.Mutex is allocated per request or per record; share a single mutex or use atomics",
        out,
    );
}

/// PERF-29: unbounded `go func(){}` spawn inside a loop or request handler.
pub(crate) fn detect_perf_32(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let on_hot_path = is_request_path(&facts.source_index);

    walk_nodes(
        unit.tree.root_node(),
        &["type_conversion_expression", "conversion_expression"],
        &mut |node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            let trimmed = text.trim();
            let is_string_to_bytes =
                trimmed.starts_with("[]byte(") || trimmed.starts_with("[]uint8(");
            let is_bytes_to_string =
                trimmed.starts_with("string(") && !trimmed.starts_with("string(\"");
            if !is_string_to_bytes && !is_bytes_to_string {
                return;
            }
            // Compile-time literal conversions (`[]byte("ok")`) do not
            // involve a runtime copy and are not a hot-path concern.
            if is_string_to_bytes && trimmed.contains("[]byte(\"") {
                return;
            }
            // Skip when the argument to []byte() is already a []byte-typed
            // variable — this is a no-op cast, not a string conversion.
            if is_string_to_bytes {
                let inner = trimmed
                    .strip_prefix("[]byte(")
                    .or_else(|| trimmed.strip_prefix("[]uint8("))
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or("");
                let is_simple_ident =
                    !inner.is_empty() && inner.chars().all(|c| c.is_alphanumeric() || c == '_');
                if is_simple_ident {
                    if let Some(&kind) = facts.var_kinds.get(inner) {
                        if kind == VarKind::Bytes {
                            return;
                        }
                    }
                }
            }
            if !on_hot_path && nearest_loop(node, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_32,
                file,
                line,
                col,
                "string <-> []byte conversion copies the underlying data on a hot path",
                out,
            );
        },
    );
}

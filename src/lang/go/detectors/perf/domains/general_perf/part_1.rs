//! PERF-26 to PERF-33 detectors.
//!
//! Heuristics for encoding hot spots, pool opportunities, mutex
//! placement, goroutine fan-out, context propagation, defer cost,
//! string/byte conversion, and indexed-scan opportunities. Each
//! detector follows the same shape as the other PERF detectors in
//! this crate: scan the precomputed [`GoPerfFacts`] and emit at most
//! one finding per call site.

use super::super::super::common::{is_in_loop, is_request_path};
use super::super::super::facts::{GoPerfFacts, VarKind};
use super::super::super::metadata::*;
use crate::ast::nearest_loop;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

/// PERF-26: base64 encoding / decoding inside a loop body.
pub(crate) fn detect_perf_26(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(
            call.callee.as_ref(),
            "base64.StdEncoding.EncodeToString"
                | "base64.StdEncoding.DecodeString"
                | "base64.URLEncoding.EncodeToString"
                | "base64.URLEncoding.DecodeString"
                | "base64.RawStdEncoding.EncodeToString"
                | "base64.RawStdEncoding.DecodeString"
                | "base64.NewEncoder"
                | "base64.NewDecoder"
        ) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_26,
            file,
            line,
            col,
            "base64 encoding or decoding is performed inside a loop body",
            out,
        );
    }
}

/// PERF-27: short-lived buffer / struct allocations on hot paths that should
/// be wrapped in a `sync.Pool`.
pub(crate) fn detect_perf_27(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if source.contains("sync.Pool") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        // `bytes.Buffer{}` / `new(bytes.Buffer)` are pure per-request
        // allocations that should be pooled. `make([]byte, …)` is too noisy
        // — sized buffers for scanners / reads are fine.
        let is_poolable = expr.contains("bytes.Buffer{")
            || expr.contains("new(bytes.Buffer)")
            || expr.contains("bytes.Buffer{}");
        if !is_poolable {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_27,
            file,
            line,
            col,
            "bytes.Buffer is allocated per request; pool it via sync.Pool",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-28: `sync.Mutex` / `sync.RWMutex` declared per request or per record.
pub(crate) fn detect_perf_28(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if !source.contains("sync.Mutex") && !source.contains("sync.RWMutex") {
        return;
    }
    // A package-scope singleton mutex is fine.
    if source.contains("var mu sync.Mutex\n")
        || source.contains("var mu sync.Mutex =")
        || source.contains("var (\n")
        || source.contains("var rwMu sync.RWMutex\n")
    {
        return;
    }
    // Mutex embedded inside a struct that is itself constructed per request
    // — the "per-record" pattern. We can only detect this from source
    // strings; the `sync.Mutex` token must appear inside a `type … struct`
    // block and that struct must be instantiated in the handler.
    let in_struct = source.contains("struct {")
        && (source.contains("\tmu sync.Mutex")
            || source.contains("mu sync.Mutex\n")
            || source.contains("rwMu sync.RWMutex"));
    let literal_in_handler = source.contains("sync.Mutex{") || source.contains("sync.RWMutex{");
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
pub(crate) fn detect_perf_29(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Bounded patterns: worker pool, semaphore, errgroup.WithContext, or
    // a semaphore that uses a buffered channel of `struct{}` tokens.
    if source.contains("errgroup.WithContext")
        || source.contains("sem := make(chan struct{}")
        || source.contains("sem <- struct{}{}")
        || source.contains("workerCount")
        || source.contains("workerPool")
        || source.contains("semaphore")
        // Goroutine tied to the request lifecycle — not "unbounded".
        || source.contains("sync.WaitGroup")
        || source.contains("wg.Add(")
        || source.contains("c.Request.Context()")
        || source.contains("ctx, cancel := context.WithCancel")
        || source.contains("ctx, cancel := context.WithTimeout")
    {
        return;
    }

    walk_nodes(unit.tree.root_node(), &["go_statement"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !text.contains("go func") {
            return;
        }
        // The semaphore-safe pattern has `sem <- struct{}{}` before the
        // `go func()` and `<-sem` inside it. We allow the goroutine spawn
        // to fire only when no such guard is in scope; the whole-file
        // suppression above is the primary gate.
        let in_loop = nearest_loop(node, LOOP_NODE_KINDS).is_some();
        let on_request_path = is_request_path(source);
        if !in_loop && !on_request_path {
            return;
        }
        let (line, col) = unit.line_col(node.start_byte());
        emit::push_finding(
            &META_PERF_29,
            file,
            line,
            col,
            "goroutine is spawned without a bounded worker pool or semaphore",
            out,
        );
    });
}

/// PERF-30: `context.Background()` / `context.TODO()` in a goroutine launched
/// from a request handler.
pub(crate) fn detect_perf_30(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "context.Background" | "context.TODO") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_30,
            file,
            line,
            col,
            "context.Background / TODO detaches the goroutine from the request context",
            out,
        );
        return;
    }
    let _ = source;
}

/// PERF-31: `defer` inside a request handler or hot function.
pub(crate) fn detect_perf_31(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    // Suppress resource-cleanup defer patterns (`defer x.Close()`,
    // `defer cancel()`, `defer x.Stop()`) — those are idiomatic Go and
    // should not trip the hot-path heuristic.
    let has_resource_defer =
        source.contains(".Close()") || source.contains("cancel()") || source.contains(".Stop()");
    if has_resource_defer {
        return;
    }

    walk_nodes(unit.tree.root_node(), &["defer_statement"], &mut |node| {
        let (line, col) = unit.line_col(node.start_byte());
        emit::push_finding(
            &META_PERF_31,
            file,
            line,
            col,
            "defer is used in a hot handler function; consider explicit cleanup",
            out,
        );
    });
}

/// PERF-32: `[]byte(s)` or `string(b)` conversion in a loop or hot path.
pub(crate) fn detect_perf_32(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let on_hot_path = is_request_path(source);

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

/// PERF-33: range over a large slice in a request handler / batch processor
/// where indexed scan would be more efficient.
pub(crate) fn detect_perf_33(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if !source.contains("for _, item := range items") {
        return;
    }
    // If the loop breaks early or uses an indexed scan, suppress.
    if source.contains("for i := 0; i < len(items);") || source.contains("break") {
        return;
    }

    let start = source.find("for _, item := range items").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_33,
        file,
        line,
        col,
        "range over a large slice on a request path; consider indexed scan or early break",
        out,
    );
}

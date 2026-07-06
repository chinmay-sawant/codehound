#![allow(dead_code)]
//! PERF-91 through PERF-95: Fiber / fasthttp framework performance detectors.

use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-91: Fiber handler allocates per-request buffers (c.Request.Body,
/// c.Response.BodyWriter, bytes.NewReader) without using sync.Pool.
pub(crate) fn detect_perf_91(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(FIBER_MARKERS) {
        return;
    }
    if facts.source_index.has("sync.Pool") || facts.source_index.has("bytePool") {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if matches!(
            callee,
            "c.Request.Body" | "c.Request.BodyStream" | "c.Response.BodyWriter" | "bytes.NewReader"
        ) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_91,
                file,
                line,
                col,
                "Fiber handler allocates a per-request buffer without using a sync.Pool; reuse buffers across requests",
                out,
            );
            return;
        }
    }
}

/// PERF-92: Fiber handler captures c inside a goroutine instead of using
/// c.UserContext().
pub(crate) fn detect_perf_92(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !facts.source_index.has_any(FIBER_MARKERS) {
        return;
    }
    walk_nodes(unit.tree.root_node(), &["go_statement"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if text.contains("c.UserContext()") || text.contains("c.Context()") {
            return;
        }
        let bytes = text.as_bytes();
        let captures_c = bytes.iter().enumerate().any(|(idx, &b)| {
            b == b'c'
                && (idx == 0 || !is_ident_byte(bytes[idx - 1]))
                && (idx + 1 == bytes.len() || !is_ident_byte(bytes[idx + 1]))
        });
        if captures_c {
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_92,
                file,
                line,
                col,
                "Fiber *fiber.Ctx is captured inside a goroutine; the ctx is reused per request and will race — use c.UserContext()",
                out,
            );
        }
    });
}

/// PERF-93: Fiber handler allocates JSON encoder (c.JSON / json.NewEncoder)
/// per request on a hot path.
pub(crate) fn detect_perf_93(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(FIBER_MARKERS) {
        return;
    }
    if facts.source_index.has("encoderPool") || facts.source_index.has("jsonPool") {
        return;
    }
    if !facts.source_index.has("c.JSON(") && !facts.source_index.has("json.NewEncoder(") {
        return;
    }
    for call in &facts.calls {
        if matches!(call.callee.as_ref(), "c.JSON" | "json.NewEncoder") {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_93,
                file,
                line,
                col,
                "JSON response is allocated per request in a Fiber handler; reuse a pooled encoder",
                out,
            );
            return;
        }
    }
}

/// PERF-94: Fiber handler uses io.ReadAll on the request body or calls
/// c.Body() where c.PostBody() zero-copy would suffice.
pub(crate) fn detect_perf_94(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(FIBER_MARKERS) {
        return;
    }
    for call in &facts.calls {
        match call.callee.as_ref() {
            "io.ReadAll" => {
                if let Some(arg) = call.arguments.first() {
                    let t = arg.as_ref();
                    if t.contains("RequestBodyStream")
                        || t.contains("BodyStream")
                        || t.contains("c.Request.Body")
                    {
                        let (line, col) = unit.line_col(call.start_byte);
                        emit::push_finding(
                            &META_PERF_94,
                            file,
                            line,
                            col,
                            "io.ReadAll on a Fiber body stream triggers an extra copy; use c.PostBody() for zero-copy reads",
                            out,
                        );
                        return;
                    }
                }
            }
            "c.Body" => {
                let (line, col) = unit.line_col(call.start_byte);
                emit::push_finding(
                    &META_PERF_94,
                    file,
                    line,
                    col,
                    "c.Body() copies the request body; use c.PostBody() for zero-copy access in Fiber handlers",
                    out,
                );
                return;
            }
            _ => {}
        }
    }
}

/// PERF-95: Fiber app registers many app.Use middleware calls in a row.
pub(crate) fn detect_perf_95(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has("fiber.New(")
        && !facts.source_index.has("fiber.App")
        && !facts.source_index.has("app.Use(")
        && !facts.source_index.has("app.Group(")
    {
        return;
    }
    let first = facts.calls.iter().find(|c| c.callee.as_ref() == "app.Use");
    let use_count = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "app.Use")
        .count();
    if use_count < 2 {
        return;
    }
    if let Some(call) = first {
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_95,
            file,
            line,
            col,
            "Fiber app registers multiple app.Use middlewares; group them by route to keep the per-request chain small",
            out,
        );
    }
}

use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_29(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Bounded patterns: worker pool, semaphore, errgroup.WithContext, or
    // a semaphore that uses a buffered channel of `struct{}` tokens.
    if facts.source_index.has("errgroup.WithContext")
        || facts.source_index.has("sem := make(chan struct{}")
        || facts.source_index.has("sem <- struct{}{}")
        || facts.source_index.has("workerCount")
        || facts.source_index.has("workerPool")
        || facts.source_index.has("semaphore")
        // Goroutine tied to the request lifecycle — not "unbounded".
        || facts.source_index.has("sync.WaitGroup")
        || facts.source_index.has("wg.Add(")
        || facts.source_index.has("c.Request.Context()")
        || facts.source_index.has("ctx, cancel := context.WithCancel")
        || facts.source_index.has("ctx, cancel := context.WithTimeout")
    {
        return;
    }

    for &(start_byte, end_byte) in &facts.go_starts {
        let text = &source[start_byte..end_byte];
        if !text.contains("go func") {
            continue;
        }
        let in_loop = facts
            .for_ranges
            .iter()
            .any(|&(s, e)| s <= start_byte && start_byte <= e);
        let on_request_path = is_request_path(&facts.source_index);
        if !in_loop && !on_request_path {
            continue;
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_29,
            file,
            line,
            col,
            "goroutine is spawned without a bounded worker pool or semaphore",
            out,
        );
    }
}

/// PERF-30: `context.Background()` / `context.TODO()` in a goroutine launched
/// from a request handler.
pub(crate) fn detect_perf_30(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
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
pub(crate) fn detect_perf_31(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !is_request_path(&facts.source_index) {
        return;
    }
    // Suppress idiomatic cleanup defers — Close/cancel/Stop/pool Put/Unlock.
    let source = unit.source.as_ref();
    let has_resource_defer = facts.source_index.has(".Close()")
        || facts.source_index.has("cancel()")
        || facts.source_index.has(".Stop()")
        || source.contains("defer")
            && (source.contains(".Put(")
                || source.contains(".Unlock()")
                || source.contains(".RUnlock()")
                || source.contains("bufPool")
                || source.contains("sync.Pool"));
    if has_resource_defer {
        return;
    }

    for &(start_byte, _end_byte) in &facts.defer_starts {
        // Prefer same-function body: skip defers that are clearly pool/mutex cleanup.
        if let Some(body) =
            crate::lang::go::detectors::perf::common::enclosing_function_body(source, start_byte)
        {
            let defer_snip = &source[start_byte..(start_byte + 80).min(source.len())];
            if defer_snip.contains(".Put(")
                || defer_snip.contains(".Close(")
                || defer_snip.contains("cancel(")
                || defer_snip.contains(".Unlock(")
                || defer_snip.contains(".RUnlock(")
                || defer_snip.contains(".Stop(")
            {
                continue;
            }
            let _ = body;
        }
        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_PERF_31,
            file,
            line,
            col,
            "defer is used in a hot handler function; consider explicit cleanup",
            out,
        );
    }
}

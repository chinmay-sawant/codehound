//! Generic hot-path fan-out, bulk buffer sizing, and signing-buffer ownership.
//!
//! These detectors match **stdlib shapes**, not product-local PDF/font APIs.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{
    enclosing_function_body, enclosing_function_name,
};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// Minimum fixed `Grow(N)` capacity treated as bulk (avoids flagging tiny Grow(8)).
const BULK_GROW_MIN: u64 = 4096;

/// PERF-232: Parallel fan-out without a concurrency bound (SetLimit / semaphore).
pub(crate) fn detect_perf_232(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();

    for &(loop_start, loop_end) in &facts.for_ranges {
        let end = loop_end.min(source.len()).max(loop_start);
        let loop_text = &source[loop_start..end];
        if !has_parallel_fanout(loop_text) {
            continue;
        }

        let body = enclosing_function_body(source, loop_start).unwrap_or(source);
        // Scope to errgroup: SetLimit is that API's concurrency control. Bare
        // WaitGroup + go is common and intentional without a semaphore, so do
        // not flag it here (avoids FP storms on ordinary worker fan-out).
        let uses_errgroup = body.contains("errgroup.Group")
            || body.contains("errgroup.WithContext")
            || body.contains("errgroup.");
        if !uses_errgroup || !loop_text.contains(".Go(") || has_concurrency_bound(body) {
            continue;
        }

        let (line, col) = unit.line_col(loop_start);
        emit::push_finding(
            &META_PERF_232,
            file,
            line,
            col,
            "parallel work fan-out has no SetLimit or semaphore bound; cap concurrency before spawning per-item work",
            out,
        );
        return;
    }
}

/// PERF-234: Fixed bulk Grow(N) or pooled buffer Reset without capacity planning.
pub(crate) fn detect_perf_234(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();

    // Any receiver: `buf.Grow(65536)` / `stream.Grow(4096)` with a large fixed literal.
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(".Grow(") {
        let start = search + rel;
        let after = &source[start + ".Grow(".len()..];
        let digits = after
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>();
        if !digits.is_empty() {
            if let Ok(n) = digits.parse::<u64>() {
                if n >= BULK_GROW_MIN {
                    let (line, col) = unit.line_col(start);
                    emit::push_finding(
                        &META_PERF_234,
                        file,
                        line,
                        col,
                        "bulk buffer uses a fixed Grow size; derive capacity from the input workload when it is known",
                        out,
                    );
                    return;
                }
            }
        }
        search = start + 4;
    }

    // Pooled *bytes.Buffer: Get → Reset → Write without any Grow in the unit.
    // Shape is stdlib/sync.Pool + bytes, not a product buffer name.
    if source.contains("Get().(*bytes.Buffer)")
        && source.contains(".Reset()")
        && (source.contains(".Write(")
            || source.contains(".WriteString(")
            || source.contains(".WriteByte("))
        && !source.contains(".Grow(")
    {
        let byte = source
            .find("Get().(*bytes.Buffer)")
            .or_else(|| source.find(".Reset()"))
            .unwrap_or(0);
        let (line, col) = unit.line_col(byte);
        emit::push_finding(
            &META_PERF_234,
            file,
            line,
            col,
            "reused bulk buffer is reset without a workload-based Grow before assembly writes",
            out,
        );
    }
}

/// PERF-236: Full buffer clone on a signing path (owned writable buffer preferred).
pub(crate) fn detect_perf_236(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();
    let Some(clone) = source.find("bytes.Clone(") else {
        return;
    };
    let function = enclosing_function_name(source, clone)
        .unwrap_or("")
        .to_ascii_lowercase();
    // Signing/finalize helpers only — not every Clone in the file.
    if !(function.contains("sign") || function.contains("signature")) {
        return;
    }

    let (line, col) = unit.line_col(clone);
    emit::push_finding(
        &META_PERF_236,
        file,
        line,
        col,
        "signing path clones the complete buffer; prefer an owned writable buffer or in-place patching of reserved holes",
        out,
    );
}

fn has_parallel_fanout(loop_text: &str) -> bool {
    loop_text.contains(".Go(")
        || loop_text.contains("go func")
        || (loop_text.contains("wg.Add(") && loop_text.contains("go "))
}

fn has_concurrency_bound(body: &str) -> bool {
    body.contains("SetLimit(")
        || body.contains("semaphore")
        || body.contains("sem.Acquire(")
        || body.contains("Acquire(ctx")
}

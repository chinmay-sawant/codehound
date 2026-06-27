//! PERF-107, 137, 141, 149, 161, 163, 170, 176, 195: I/O and runtime misuse.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::is_in_loop;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{emit, Finding};

/// PERF-107: `encoding/binary.Read` / `binary.Write` inside a loop body
/// — the encoding layer makes a function call per element with
/// runtime reflection.
pub(crate) fn detect_perf_107(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !matches!(call.callee.as_ref(), "binary.Read" | "binary.Write") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_107,
            file,
            line,
            col,
            "encoding/binary Read/Write inside a loop uses reflection; reuse a pre-encoded buffer or hand-roll the byte order",
            out,
        );
    }
}

/// PERF-137: `runtime.Caller` inside a request handler. We
/// restrict the check to function literals whose enclosing
/// function has `http.ResponseWriter` in its signature, so a
/// package-level `var sourceTag = func() { runtime.Caller(0) }`
/// doesn't false-positive (that pattern caches the value once
/// at startup, which is the safe alternative).
pub(crate) fn detect_perf_137(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("runtime.Caller") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.Caller" {
            continue;
        }
        // The enclosing function must have `http.ResponseWriter`
        // in its signature (i.e. be a request handler). Look
        // at the 1 KiB before the call.
        let func_start = call.start_byte.saturating_sub(1024);
        let func_window = &source[func_start..call.start_byte];
        let is_handler = func_window.contains("http.ResponseWriter")
            || func_window.contains("gin.Context")
            || func_window.contains("echo.Context")
            || func_window.contains("*fiber.Ctx");
        if !is_handler && !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_137,
            file,
            line,
            col,
            "runtime.Caller on a hot path; pass a constant stack index or use a faster source-location API",
            out,
        );
    }
}

/// PERF-141: `r.URL.Query()` called more than once in the same
/// handler. Each call re-parses the query string.
pub(crate) fn detect_perf_141(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has(".URL.Query()") {
        return;
    }

    let mut search_from = 0;
    let mut first_location: Option<(usize, usize)> = None;
    let mut count = 0usize;
    while let Some(rel) = source[search_from..].find(".URL.Query()") {
        let start = search_from + rel;
        if first_location.is_none() {
            first_location = Some(unit.line_col(start));
        }
        count += 1;
        search_from = start + ".URL.Query()".len();
    }
    if count >= 2 {
        if let Some((line, col)) = first_location {
            emit::push_finding(
                &META_PERF_141,
                file,
                line,
                col,
                "r.URL.Query() called repeatedly; cache the result in a local variable at the top of the handler",
                out,
            );
        }
    }
}

/// PERF-149: `conn.Read` / `conn.Write` on a `net.Conn` without
/// a preceding `SetReadDeadline` / `SetWriteDeadline`. The
/// operation can block forever. We restrict the check to call
/// sites whose method receiver is literally `conn` (or starts
/// with `conn.` / `Conn.`) so we don't false-positive on
/// `hash.Hash.Write`, `bytes.Buffer.Write`, etc.
pub(crate) fn detect_perf_149(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        let method = call.callee.as_ref();
        // Match only obvious net.Conn-shaped call sites:
        // the method must be exactly `.Read` or `.Write` on a
        // `conn` / `Conn` receiver. We don't match arbitrary
        // method names that start with `conn.` because that
        // includes `conn.SetReadDeadline` (which is the safe
        // alternative).
        let is_read = method.ends_with(".Read") && !method.ends_with("ReadDeadline");
        let is_write = method.ends_with(".Write") && !method.ends_with("WriteDeadline");
        if !is_read && !is_write {
            continue;
        }
        let receiver_ok = method == "conn.Read"
            || method == "conn.Write"
            || method == "Conn.Read"
            || method == "Conn.Write"
            || (method.starts_with("c.")
                && (method.ends_with(".Read") || method.ends_with(".Write")));
        if !receiver_ok {
            continue;
        }
        // The file must be using the `net` package — otherwise
        // the receiver is a `hash.Hash` / `bytes.Buffer` /
        // similar.
        if !facts.source_index.has("net.Conn")
            && !facts.source_index.has("net.Dial")
            && !facts.source_index.has("net.Listen")
        {
            continue;
        }
        // Look at the prior 1 KiB of source for a SetReadDeadline
        // / SetWriteDeadline call. If absent, flag.
        let window_start = call.start_byte.saturating_sub(1024);
        let window = &source[window_start..call.start_byte];
        if window.contains("SetReadDeadline")
            || window.contains("SetWriteDeadline")
            || window.contains("SetDeadline")
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_149,
            file,
            line,
            col,
            "conn.Read / conn.Write without a preceding SetReadDeadline / SetWriteDeadline; the operation can block indefinitely",
            out,
        );
    }
}

/// PERF-161: `for rows.Next()` block without a follow-up
/// `rows.Err()` call. The `Next()` loop distinguishes "no more
/// rows" from a real error only when `rows.Err()` is checked.
pub(crate) fn detect_perf_161(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("rows.Next()") || !facts.source_index.has("rows.Close()") {
        return;
    }
    // A `for rows.Next()` block is a finding if the surrounding
    // function does NOT call `rows.Err()`.
    if facts.source_index.has("rows.Err()") {
        return;
    }
    let Some(rel) = source.find("rows.Next()") else {
        return;
    };
    let (line, col) = unit.line_col(rel);
    emit::push_finding(
        &META_PERF_161,
        file,
        line,
        col,
        "for rows.Next() block without a follow-up rows.Err() call; check the error to distinguish 'no more rows' from a real error",
        out,
    );
}

/// PERF-163: `db.Query` consumed with a single `if rows.Next() {`
/// check (not a `for rows.Next()` loop). Use `db.QueryRow` for
/// single-row queries — it handles `rows.Close()` for you.
pub(crate) fn detect_perf_163(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    if !facts.source_index.has("db.Query(") {
        return;
    }
    if !facts.source_index.has("rows.Next()") {
        return;
    }
    // Require the consumption shape `if rows.Next() {` (single
    // check) rather than `for rows.Next() {` (loop). The for
    // loop shape is the multi-row case where db.Query is correct.
    if !facts.source_index.has("if rows.Next()") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "db.Query" && !call.callee.as_ref().ends_with(".Query") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_163,
            file,
            line,
            col,
            "db.Query consumed with a single if rows.Next() check; use db.QueryRow for single-row queries",
            out,
        );
    }
}

/// PERF-170: `sync.Once.Do` inside a function that takes
/// `http.ResponseWriter` (a request handler). The atomic-load-and-
/// branch is small but adds up when the handler is called many
/// times per second. We restrict the check to functions whose
/// signature contains `http.ResponseWriter` so the once in a
/// non-handler helper (e.g. `loadReport`) doesn't false-positive.
pub(crate) fn detect_perf_170(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("sync.Once") || !facts.source_index.has(".Do(") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(".Do(") {
        let start = search_from + rel;
        // Look back ~16 bytes to confirm this is `once.Do(`.
        let pre_start = start.saturating_sub(16);
        let pre = &source[pre_start..start];
        // Variable name can be `once` / `Once` / `ONCE` etc.
        if !pre.to_lowercase().contains("once") {
            search_from = start + ".Do(".len();
            continue;
        }
        // The function containing the `.Do(` must have a
        // `http.ResponseWriter` parameter. We approximate by
        // looking at the 1 KiB before the call for the function
        // signature. This is a coarse check but works for the
        // common handler shape.
        let func_start = start.saturating_sub(1024);
        let func_window = &source[func_start..start];
        let is_handler = func_window.contains("http.ResponseWriter")
            || func_window.contains("gin.Context")
            || func_window.contains("echo.Context")
            || func_window.contains("*fiber.Ctx");
        if !is_handler {
            search_from = start + ".Do(".len();
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_170,
            file,
            line,
            col,
            "sync.Once.Do in a request handler; use a sync/atomic.Bool or hoist the once out of the request path",
            out,
        );
        search_from = start + ".Do(".len();
    }
}

/// PERF-176: `io.Copy` inside a loop. Each call allocates a
/// 32 KiB buffer; use `io.CopyBuffer` with a pooled buffer.
pub(crate) fn detect_perf_176(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    for call in &facts.calls {
        if call.callee.as_ref() != "io.Copy" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_176,
            file,
            line,
            col,
            "io.Copy inside a loop allocates a 32 KiB buffer per call; use io.CopyBuffer with a pooled buffer",
            out,
        );
    }
}

/// PERF-195: `log.Fatal*` / `log.Panic*` inside a `go func()`
/// body. The process-level call belongs in the request
/// handler, not a goroutine.
pub(crate) fn detect_perf_195(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        let is_fatal = matches!(
            callee,
            "log.Fatal" | "log.Fatalf" | "log.Fatalln" | "log.Panic" | "log.Panicf" | "log.Panicln"
        );
        if !is_fatal {
            continue;
        }
        // The call must live inside a `go func()` body. We
        // approximate by checking the source window — the
        // nearest `go func()` start before the call.
        let window_start = call.start_byte.saturating_sub(2048);
        let window = &source[window_start..call.start_byte];
        if !window.contains("go func()") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_195,
            file,
            line,
            col,
            "log.Fatal / log.Panic inside a goroutine; return the error and let the caller decide whether to terminate the process",
            out,
        );
    }
}

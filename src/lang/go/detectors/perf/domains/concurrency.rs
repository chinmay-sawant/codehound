//! Migrated from hot_path_misc.rs: domain-specific Concurrency PERF detectors.
//!
//! PERF-148, PERF-167, PERF-172, PERF-173, PERF-174, PERF-175, PERF-183, PERF-193, PERF-194

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{char_boundary, file_has_handler, is_handler_shaped, is_in_loop};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_148(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("make(chan ") {
        return;
    }
    if !source.contains(" <- ") {
        return;
    }

    // Find each `make(chan T)` and check for a receive on the
    // same channel within the same function. We use a simple
    // heuristic: if the file uses `make(chan T)` AND has any
    // `ch <- ` send but NO `<-ch` receive at all, flag the
    // first make call.
    let has_receive = source.contains("<-ch")
        || source.contains("<- ch")
        || source.contains("for v := range ch")
        || source.contains("for range ch");
    if has_receive {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("make(chan ") {
        let start = search_from + rel;
        let stmt_end = source[start..]
            .find(['\n', ';'])
            .map(|i| start + i)
            .unwrap_or(source.len());
        let make_stmt = &source[start..stmt_end];
        let is_unbuffered = if make_stmt.contains(", ") {
            let after_comma = make_stmt
                .rfind(", ")
                .map(|p| &make_stmt[p + 2..])
                .unwrap_or("");
            let cap_str: String = after_comma
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            cap_str == "0" || cap_str.is_empty()
        } else {
            true
        };
        if is_unbuffered {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_148,
                file,
                line,
                col,
                "unbuffered channel created with no receive in this function; the sender may block forever if the receiver exits early",
                out,
            );
            return;
        }
        search_from = stmt_end;
    }
}

pub(crate) fn detect_perf_167(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Add") {
            continue;
        }
        // Approximate: the most recent `go func()` start must be
        // before the call and there must be no `func ` boundary
        // between them that is not a `go func()`.
        let window_start = call.start_byte.saturating_sub(2048);
        let window = &source[char_boundary(source, window_start)..call.start_byte];
        let go_idx = window.rfind("go func()");
        let Some(go_idx) = go_idx else {
            continue;
        };
        // The body of the goroutine starts after the `{` of `go func() { ... }`.
        // If we see a closing `}` between the `go func()` and the call,
        // the call is in a different scope.
        let after = &window[go_idx..];
        let depth = after.bytes().filter(|&b| b == b'{').count() as i32
            - after.bytes().filter(|&b| b == b'}').count() as i32;
        if depth <= 0 {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_167,
            file,
            line,
            col,
            "wg.Add inside a goroutine body; the Add must happen before the goroutine is started",
            out,
        );
    }
}

pub(crate) fn detect_perf_172(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains(".Wait()") {
        return;
    }
    if !source.contains("go ") {
        return;
    }
    // Only fire when wg.Wait() is followed by a response write
    // (c.JSON, w.Write, etc.), meaning the handler is truly
    // blocked on the goroutine before writing the response.
    let wait_pos = match source.rfind(".Wait()") {
        Some(p) => p,
        None => return,
    };
    let tail = &source[wait_pos + 7..];
    let has_response_after = tail.contains(".JSON(")
        || tail.contains(".Write(")
        || tail.contains(".WriteHeader(")
        || tail.contains(".String(")
        || tail.contains(".HTML(");
    if !has_response_after {
        return;
    }
    // Suppress when a context-cancellation pattern exists in the
    // window before the wait call.
    let window_start = wait_pos.saturating_sub(2048);
    let window = &source[char_boundary(source, window_start)..wait_pos];
    if window.contains("ctx := c.Request.Context()")
        || window.contains("ctx := r.Context()")
        || window.contains("ctx, cancel := context.WithCancel")
        || window.contains("ctx := c.Copy()")
        || window.contains("case <-ctx.Done()")
    {
        return;
    }
    // Suppress when the goroutine calls a real work function
    // (not just wg.Done). This means the wg.Wait is intentional
    // bounded concurrency, not a blocking anti-pattern.
    let go_func_pos = source[..wait_pos].rfind("go func");
    if let Some(gfp) = go_func_pos {
        let go_body = &source[gfp..wait_pos];
        let has_work_call = go_body.lines().any(|l| {
            let t = l.trim();
            t.contains('(')
                && !t.contains("wg.Done")
                && !t.contains("wg.Add")
                && !t.contains("go func")
                && !t.contains("defer func")
                && t != "}()"
                && t != "})"
                && !t.starts_with("}(")
        });
        if has_work_call {
            return;
        }
    }
    let (line, col) = unit.line_col(wait_pos);
    emit::push_finding(
        &META_PERF_172,
        file,
        line,
        col,
        "wg.Wait in a request handler blocks the serving goroutine; use context cancellation or errgroup instead",
        out,
    );
}

pub(crate) fn detect_perf_173(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if call.callee.as_ref() != "time.Tick" {
            continue;
        }
        // The rest of the function must NOT call any `Stop()` for
        // an associated ticker.
        let window_after = &source[call.start_byte..];
        if window_after.contains(".Stop()") {
            continue;
        }
        // Bare `for range time.Tick(...)` cannot be stopped; the
        // user already knows this. We suppress it by checking
        // whether `range ` immediately precedes the call (within
        // ~32 bytes).
        let pre_start = call.start_byte.saturating_sub(32);
        let pre = &source[char_boundary(source, pre_start)..call.start_byte];
        if pre.contains("range ") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_173,
            file,
            line,
            col,
            "time.Tick returns an unstoppable ticker; use time.NewTicker and call ticker.Stop() when done",
            out,
        );
    }
}

pub(crate) fn detect_perf_174(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if call.callee.as_ref() != "close" {
            continue;
        }
        let Some(arg) = call.arguments.first() else {
            continue;
        };
        let arg_text = arg.as_ref();
        let ch = arg_text.trim().trim_end_matches(',');
        if ch.is_empty() {
            continue;
        }
        // Find the function start (the most recent `func` keyword
        // before the call) and the function end (the next `}` at
        // the same depth). We approximate by looking for the
        // previous `func ` and the matching close brace.
        let func_start = source[..call.start_byte].rfind("func ").unwrap_or(0);
        let body_start = source[func_start..].find('{').map(|i| func_start + i + 1);
        let body_start = body_start.unwrap_or(source.len());
        // Find the matching `}` from the body start by counting
        // braces. We accept the first `}` whose depth is zero
        // relative to body_start.
        let after_body = &source[body_start..];
        let mut depth: i32 = 1;
        let mut body_end = after_body.len();
        for (i, c) in after_body.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        body_end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body_end = body_start + body_end;
        // Look for `<-ch` or `<- ch` in the function body.
        let body = &source[body_start..body_end];
        let recv = format!("<-{ch}");
        let recv_space = format!("<- {ch}");
        if body.contains(&recv) || body.contains(&recv_space) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_174,
                file,
                line,
                col,
                "close() called on a channel that is also received on in the same function; only the sender should close a channel",
                out,
            );
        }
    }
}

pub(crate) fn detect_perf_175(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for {") {
        return;
    }
    if !source.contains("<-") {
        return;
    }

    // The `for { ... <-ch ... }` pattern is hard to detect via the
    // simple fact layer. We approximate by looking for a `for {`
    // body that contains a `<-ch` and no `select` (which is the
    // safe alternative). The naive substring scan picks up the
    // common case while leaving non-trivial cases to higher-tier
    // detectors.
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("for {") {
        let start = search_from + rel;
        let body_window = &source[start..char_boundary(source, (start + 1024).min(source.len()))];
        if !body_window.contains("<-") {
            search_from = start + "for {".len();
            continue;
        }
        if body_window.contains("select ") || body_window.contains("time.Sleep(") {
            search_from = start + "for {".len();
            continue;
        }
        // Find the body and ensure the receive is inside the
        // immediate block.
        let Some(open_brace) = body_window.find('{') else {
            search_from = start + "for {".len();
            continue;
        };
        let after = &body_window[open_brace + 1..];
        if after.contains("<-") {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_175,
                file,
                line,
                col,
                "for { ... <-ch ... } spins on a buffered channel; use a select with default or wait on a done channel",
                out,
            );
            return;
        }
        search_from = start + "for {".len();
    }
}

pub(crate) fn detect_perf_183(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(
            callee,
            "context.WithTimeout" | "context.WithDeadline" | "context.WithCancel"
        ) {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_183,
            file,
            line,
            col,
            "context.WithTimeout inside a loop; create the context once outside the loop and derive per-iteration values via context.WithValue",
            out,
        );
    }
}

pub(crate) fn detect_perf_193(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if call.callee.as_ref() != "time.After" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        // The loop body must NOT contain a `t.Reset(` or
        // `timer.Reset(` to be a finding. We approximate with a
        // 1 KiB scan around the call.
        let window = &source[call.start_byte..char_boundary(source, (call.start_byte + 1024).min(source.len()))];
        if window.contains(".Reset(") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_193,
            file,
            line,
            col,
            "time.After inside a loop without a reusable timer; hoist a *time.Timer and call t.Reset(d) per iteration",
            out,
        );
    }
}

pub(crate) fn detect_perf_194(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "time.Sleep" {
            continue;
        }
        if !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_194,
            file,
            line,
            col,
            "time.Sleep in a request handler; use a channel / context cancellation or a longer-lived ticker to poll",
            out,
        );
    }
}

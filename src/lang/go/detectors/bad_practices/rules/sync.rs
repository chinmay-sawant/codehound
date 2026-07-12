//! BP-6, BP-7, BP-8, BP-9, BP-12, BP-14 — concurrency/synchronisation bad practices.

use super::super::source_index::SourceIndex;
use super::helpers::{line_start_byte, push_at};
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-6: sync.WaitGroup.Add inside the goroutine it tracks.
///
/// Uses brace-depth over the `go func…{…}` literal body instead of a
/// line-level state machine (which mis-handles nested blocks).
pub(crate) fn detect_bp_6_waitgroup_add_inside_goroutine(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !index.has("go func") || !index.has(".Add(") {
        return;
    }
    let mut search = 0;
    while let Some(rel) = source[search..].find("go func") {
        let start = search + rel;
        // Find the opening brace of the func literal.
        let Some(brace_rel) = source[start..].find('{') else {
            search = start + 7;
            continue;
        };
        let body_open = start + brace_rel;
        let Some(body) = braced_block(source, body_open) else {
            search = body_open + 1;
            continue;
        };
        if let Some(add_rel) = body.find(".Add(") {
            let byte = body_open + add_rel;
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_6_META,
                byte,
                "WaitGroup.Add is inside the goroutine; call Add before launching it",
            );
        }
        search = body_open + body.len().max(1);
    }
}

/// BP-7: sync.Mutex copied by function parameter value.
pub(crate) fn detect_bp_7_mutex_passed_by_value(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("func ")
            && trimmed.contains(" sync.Mutex")
            && !trimmed.contains("*sync.Mutex")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_7_META,
                line_start_byte(source, idx) + line.find("sync.Mutex").unwrap_or(0),
                "sync.Mutex is passed by value; pass *sync.Mutex to avoid copying lock state",
            );
        }
    }
}

/// BP-8: deferred unlock when a mutex is held **by value** (copied).
///
/// Does **not** flag the idiomatic `mu.Lock(); defer mu.Unlock()` on a
/// `*sync.Mutex` or package-level mutex — only by-value parameters/copies.
pub(crate) fn detect_bp_8_defer_unlock_on_mutex_copy(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !(index.has("defer ") && index.has(".Unlock()")) {
        return;
    }
    // Require evidence of a by-value mutex parameter (not *sync.Mutex).
    let has_value_mutex_param = source.lines().any(|line| {
        let t = line.trim();
        t.starts_with("func ")
            && t.contains("sync.Mutex")
            && !t.contains("*sync.Mutex")
            && !t.contains("*sync.RWMutex")
            && (t.contains("sync.Mutex)") || t.contains("sync.Mutex,") || t.contains("sync.Mutex "))
    });
    if !has_value_mutex_param {
        return;
    }
    for (idx, line) in source.lines().enumerate() {
        if line.trim().starts_with("defer ") && line.contains(".Unlock()") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_8_META,
                line_start_byte(source, idx) + line.find(".Unlock()").unwrap_or(0),
                "defer unlock is operating on a mutex value copy; pass *sync.Mutex",
            );
        }
    }
}

/// BP-9: select without default, timeout, or context cancellation.
///
/// Uses brace-depth matching for the select body (not first `}`).
pub(crate) fn detect_bp_9_select_without_escape(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    let mut search = 0;
    while let Some(rel) = source[search..].find("select") {
        let start = search + rel;
        // Require `select {` (allow whitespace before brace).
        let after = source[start + "select".len()..].trim_start();
        if !after.starts_with('{') {
            search = start + 6;
            continue;
        }
        let brace_pos =
            start + "select".len() + (source[start + "select".len()..].len() - after.len());
        let Some(block) = braced_block(source, brace_pos) else {
            search = brace_pos + 1;
            continue;
        };
        let has_escape = block.contains("default:")
            || block.contains("time.After(")
            || block.contains("time.NewTimer(")
            || block.contains("ctx.Done()")
            || block.contains("context.Done()")
            || block.contains("<-stop")
            || block.contains("<-done")
            || block.contains("<-ctx.Done()");
        if !has_escape {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_9_META,
                start,
                "select can block indefinitely without default, timeout, or context cancellation",
            );
        }
        search = brace_pos + block.len().max(1);
    }
}

/// Extract a `{ ... }` block starting at `open` (must point at `{`).
fn braced_block(source: &str, open: usize) -> Option<&str> {
    if source.as_bytes().get(open).is_none_or(|b| *b != b'{') {
        return None;
    }
    let mut depth = 0i32;
    for (i, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&source[open..open + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// BP-12: unbuffered channel receives sends from multiple goroutines.
pub(crate) fn detect_bp_12_unbuffered_channel_send_from_multiple_goroutines(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !source.contains("make(chan") || !source.contains("go func") {
        return;
    }

    for channel in collect_unbuffered_channels(source) {
        let send_count = count_goroutine_sends(source, &channel);
        let has_receiver_fan_in = source.contains(&format!("for v := range {channel}"))
            || source.contains(&format!("for range {channel}"))
            || source.contains(&format!("<-{channel}"))
            || source.contains(&format!("case <-{channel}"));
        if send_count >= 2 && !has_receiver_fan_in {
            let byte = source.find("make(chan").unwrap_or(0);
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_12_META,
                byte,
                "unbuffered channel is sent to from multiple goroutines without an obvious coordinated receiver",
            );
            break;
        }
    }
}

/// BP-14: goroutine launched without observing ctx.Done.
pub(crate) fn detect_bp_14_goroutine_without_context_cancellation(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !source.contains("go func") || !source.contains("context.Context") {
        return;
    }

    let mut in_goroutine = false;
    let mut goroutine_start = 0usize;
    let mut goroutine_lines = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("go func") || trimmed.contains("go func(") {
            in_goroutine = true;
            goroutine_start = line_start_byte(source, idx);
            goroutine_lines.clear();
        }
        if in_goroutine {
            goroutine_lines.push(trimmed.to_string());
        }
        if in_goroutine && (trimmed == "}" || trimmed == "}()" || trimmed == "}(") {
            let body = goroutine_lines.join("\n");
            let long_running = body.contains("for {")
                || body.contains("for ")
                || body.contains("<-ticker.")
                || body.contains(".Wait()")
                || body.contains(".Recv(")
                || body.contains(".Receive(")
                || body.contains("<-work")
                || body.contains("<-jobs");
            let has_ctx_done = body.contains("ctx.Done()")
                || body.contains("context.Done()")
                || body.contains("<-ctx.Done()");
            if long_running && !has_ctx_done {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_14_META,
                    goroutine_start,
                    "long-running goroutine does not observe ctx.Done() or another cancellation path",
                );
            }
            in_goroutine = false;
        }
    }
}

fn collect_unbuffered_channels(source: &str) -> Vec<String> {
    let mut channels = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if !(trimmed.starts_with("ch :=") || trimmed.starts_with("var ")) {
            continue;
        }
        if !trimmed.contains("make(chan") || trimmed.contains(',') {
            continue;
        }
        if let Some((name, _)) = trimmed.split_once(":=") {
            channels.push(name.trim().to_string());
        } else if let Some(rest) = trimmed.strip_prefix("var ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            if !name.is_empty() {
                channels.push(name.to_string());
            }
        }
    }
    channels
}

fn count_goroutine_sends(source: &str, channel: &str) -> usize {
    let mut in_goroutine = false;
    let mut sends = 0usize;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("go func") || trimmed.contains("go func(") {
            in_goroutine = true;
        }
        if in_goroutine && trimmed.contains(&format!("{channel} <-")) {
            sends += 1;
        }
        if in_goroutine && (trimmed == "}" || trimmed == "}()") {
            in_goroutine = false;
        }
    }
    sends
}

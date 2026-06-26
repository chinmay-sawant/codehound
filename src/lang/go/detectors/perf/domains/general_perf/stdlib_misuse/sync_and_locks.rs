//! PERF-131, 132, 135, 140, 168, 171: synchronization and lock misuse.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::is_in_loop;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{emit, Finding};
use super::common::{body_has_io, is_simple_ident};
use super::ranges_and_types::is_large_struct_literal;

/// PERF-135: `gob.NewEncoder` / `gob.NewDecoder` constructed inside a
/// loop. The constructor reflects on the destination type, which is
/// expensive; create the encoder once outside the loop.
pub(crate) fn detect_perf_135(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(callee, "gob.NewEncoder" | "gob.NewDecoder") {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_135,
            file,
            line,
            col,
            "gob.NewEncoder/Decoder inside a loop reflects on the type; hoist the constructor outside the loop",
            out,
        );
    }
}

/// PERF-140: `debug.SetGCPercent(-1)` disables the GC assist entirely
/// (the GC only runs when the heap grows past `GOMEMLIMIT` or the
/// runtime is out of memory). `debug.SetGCPercent(<50)` aggressively
/// trims the heap in production. Both warrant a code review.
pub(crate) fn detect_perf_140(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("debug.SetGCPercent") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "debug.SetGCPercent" {
            continue;
        }
        let Some(arg) = call.arguments.first() else {
            continue;
        };
        let raw = arg.as_ref();
        // The argument is the literal text of the expression; the
        // common cases are `-1`, `0`, or `int` / `int32` identifiers
        // we can't resolve. We only flag literal numeric values.
        let n = raw.trim().parse::<i64>().ok();
        let Some(n) = n else {
            continue;
        };
        let bad = n == -1 || (n > 0 && n < 50);
        if !bad {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_140,
            file,
            line,
            col,
            "debug.SetGCPercent in production is rarely what you want; remove the call or document the tuning",
            out,
        );
    }
    let _ = facts;
}

/// PERF-171: a buffered channel of size 1 (`make(chan struct{}, 1)`
/// or `make(chan bool, 1)`) used purely for acquire / release. Use a
/// `sync.Mutex` instead; the channel adds an extra scheduling hop.
pub(crate) fn detect_perf_171(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "make" {
            continue;
        }
        if call.arguments.len() < 2 {
            continue;
        }
        let chan_type = call.arguments[0].as_ref();
        // Match `chan struct{}` or `chan bool`, optionally with `<-`
        // direction markers. The exact text from the AST is the type
        // expression as written.
        let chan_type_trim = chan_type.trim();
        let is_mutex_shape = chan_type_trim == "chan struct{}"
            || chan_type_trim == "chan bool"
            || chan_type_trim == "chan struct{ }"
            || chan_type_trim.starts_with("chan struct{},")
            || chan_type_trim.starts_with("chan bool,")
            || chan_type_trim.contains("chan struct{},")
            || chan_type_trim.contains("chan bool,");
        if !is_mutex_shape {
            continue;
        }
        let size = call.arguments[1].as_ref().trim();
        if size != "1" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_171,
            file,
            line,
            col,
            "make(chan T, 1) used as a mutex; use sync.Mutex instead of a channel",
            out,
        );
    }
    let _ = facts;
}

/// PERF-168: `ch <- <CompositeLiteral>` where the literal has 4+
/// fields or contains a slice / map / string field. A pointer
/// (`ch <- &T{...}`) is the correct shape.
pub(crate) fn detect_perf_168(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("<- ") {
        let start = search_from + rel;
        // Distinguish a channel send from a channel type.
        // `chan<- T` is a type with no space before `<-`; the
        // send `ch <- T` has whitespace + identifier + space +
        // `<- `. We require the character immediately before
        // `<-` to be a space.
        if start == 0 || source.as_bytes()[start - 1] != b' ' {
            search_from = start + "<- ".len();
            continue;
        }
        // The literal starts after `<- `. Look for the next `{`
        // to find the literal start.
        let arrow_end = start + "<- ".len();
        let Some(open_rel) = source[arrow_end..].find('{') else {
            search_from = arrow_end;
            continue;
        };
        let pre = &source[arrow_end..arrow_end + open_rel];
        // Reject if the channel send is already a pointer
        // (`ch <- &T{...}`) or an existing variable
        // (`ch <- someVar`).
        let trimmed_pre = pre.trim_start();
        if trimmed_pre.starts_with('&') {
            search_from = arrow_end + open_rel;
            continue;
        }
        let lit_start = arrow_end + open_rel;
        let close_rel = source[lit_start..].find('}');
        let Some(close_rel) = close_rel else {
            search_from = lit_start;
            continue;
        };
        let literal = &source[lit_start..lit_start + close_rel + 1];
        if is_large_struct_literal(literal) {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_168,
                file,
                line,
                col,
                "large struct sent by value over a channel; pass a pointer instead",
                out,
            );
        }
        search_from = lit_start + close_rel + 1;
    }
}

/// PERF-132: `go func() { ... }` whose body makes a cancellable
/// I/O call but the function literal does not accept a context.
/// The parent function has a `ctx context.Context` parameter
/// (otherwise the warning is moot); the goroutine can't propagate
/// cancellation. We require both signals: the body makes a
/// cancellable I/O call AND the parent function has a `ctx`
/// parameter. Without the parent ctx, the goroutine has nothing
/// to forward.
pub(crate) fn detect_perf_132(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("go func()") {
        return;
    }
    if !parent_has_ctx_param(source) {
        return;
    }

    for (start, _end) in &facts.go_starts {
        let go_text = &source[*start..(*start + 256).min(source.len())];
        // The function literal must be `func() { ... }` with no
        // parameters. We accept `go func() {` (no params) and
        // reject `go func(ctx context.Context) {` (has params).
        if !go_text.contains("go func()") {
            continue;
        }
        // The body is the `{ ... }` block following the
        // signature. Look for cancellable I/O inside the body.
        let body_start = go_text.find('{');
        let Some(body_start) = body_start else {
            continue;
        };
        let body_end_rel = go_text[body_start..].find('}');
        let Some(body_end_rel) = body_end_rel else {
            continue;
        };
        let body = &go_text[body_start + 1..body_start + body_end_rel];
        if !body_has_io(body) {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_132,
            file,
            line,
            col,
            "go func() body makes I/O calls but the goroutine doesn't accept a context; cancellation cannot propagate",
            out,
        );
    }
}

fn parent_has_ctx_param(source: &str) -> bool {
    // The parent function is the surrounding `func ... { ... }`
    // that contains the `go func()` site. We approximate by
    // looking for any function declaration that takes a
    // `ctx context.Context` parameter anywhere in the file.
    source.contains("ctx context.Context")
        || source.contains("ctx context.Context,")
        || source.contains("ctx context.Context)")
        || source.contains("ctx context.Context ")
}

/// PERF-131: `mu.Lock` / `mu.Unlock` wrapping only a single
/// counter-style integer operation (`x++`, `x--`, `x = x + 1`,
/// `x += 1`, or a single-line compound assignment). Use
/// `sync/atomic` instead. We deliberately restrict the body
/// match to these exact patterns to avoid false positives on
/// mutex-guarded assignments to maps / slices / pointers (which
/// are not atomic-safe).
pub(crate) fn detect_perf_131(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".Lock()") || !source.contains(".Unlock()") {
        return;
    }

    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(".Lock()") {
        let start = search_from + rel;
        let unlock_rel = source[start..].find(".Unlock()");
        let Some(unlock_rel) = unlock_rel else {
            search_from = start + ".Lock()".len();
            continue;
        };
        let unlock_start = start + unlock_rel;
        let unlock_end = unlock_start + ".Unlock()".len();
        let after_lock = start + ".Lock()".len();
        let body = &source[after_lock..unlock_start];
        eprintln!(
            "[PERF-131] body={body:?} is_counter={}",
            is_simple_counter_body(body)
        );
        if is_simple_counter_body(body) {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_131,
                file,
                line,
                col,
                "mu.Lock/mu.Unlock wraps only a simple counter op; use sync/atomic instead",
                out,
            );
        }
        search_from = unlock_end;
    }
}

fn is_simple_counter_body(body: &str) -> bool {
    // The body is the text between `.Lock()` and `.Unlock()`.
    // Split on semicolons and newlines into statements. We
    // accept only the canonical counter patterns: x++, x--,
    // x += 1, x -= 1, x = x + 1, x = x - 1. Anything else
    // (assignments to maps / slices / pointers, function calls,
    // channel operations) is not atomic-safe and the mutex is
    // justified.
    //
    // The body sometimes includes a partial leading token of
    // the receiver for `.Unlock()` (e.g. the `mu` in
    // `counter++\n\tmu.Unlock()`). We strip that trailing
    // partial-identifier by trimming back to the last newline
    // before any non-counter text.
    let inner = body.trim();
    let mut counter_op = false;
    let mut non_counter_op = false;
    for stmt in inner.split(|c: char| c == ';' || c == '\n') {
        let stmt = stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        // A partial leading identifier is a fragment of the
        // `mu.Unlock()` call we don't want to count.
        if stmt.starts_with('.') || stmt.ends_with('.') {
            continue;
        }
        // The trailing partial-identifier of the next call is
        // not a statement.
        if looks_like_partial_recv(stmt) {
            continue;
        }
        if is_counter_statement(stmt) {
            counter_op = true;
        } else {
            non_counter_op = true;
        }
    }
    counter_op && !non_counter_op
}

fn looks_like_partial_recv(stmt: &str) -> bool {
    // The partial receiver for `mu.Unlock()` looks like `mu`
    // (just an identifier with no operator). Skip it.
    is_simple_ident(stmt)
}

fn is_counter_statement(stmt: &str) -> bool {
    let stmt = stmt.trim();
    if stmt.is_empty() {
        return false;
    }
    // `x++` or `x--`
    if stmt.ends_with("++") || stmt.ends_with("--") {
        let head = stmt.trim_end_matches("++").trim_end_matches("--");
        return is_simple_ident(head.trim());
    }
    // `x += 1` or `x -= 1`
    if let Some((lhs, rhs)) = stmt.split_once("+=") {
        return rhs.trim() == "1" && is_simple_ident(lhs.trim());
    }
    if let Some((lhs, rhs)) = stmt.split_once("-=") {
        return rhs.trim() == "1" && is_simple_ident(lhs.trim());
    }
    // `x = x + 1` or `x = x - 1`
    if let Some((lhs, rhs)) = stmt.split_once('=') {
        let lhs = lhs.trim();
        let rhs = rhs.trim();
        if let Some((rlhs, rrhs)) = rhs.split_once('+') {
            return rrhs.trim() == "1"
                && is_simple_ident(rlhs.trim())
                && is_simple_ident(lhs)
                && lhs == rlhs.trim();
        }
        if let Some((rlhs, rrhs)) = rhs.split_once('-') {
            return rrhs.trim() == "1"
                && is_simple_ident(rlhs.trim())
                && is_simple_ident(lhs)
                && lhs == rlhs.trim();
        }
    }
    false
}

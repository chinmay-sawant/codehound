//! PERF-138, 159, 167, 169, 173, 174, 175, 178, 179, 180, 183, 184, 185, 186,
//! 187, 188, 193, 194, 202, 207, 210, 212: hot-path and request-handler
//! pattern detectors that resolve with a small text scan over the source.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::is_in_loop;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-138: `runtime.Stack` inside a request handler or hot loop.
/// `runtime.Stack` walks the live goroutine stack and copies every
/// frame into a new byte slice; it should never appear on a request
/// path.
pub(crate) fn detect_perf_138(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        if call.callee.as_ref() != "runtime.Stack" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_138,
            file,
            line,
            col,
            "runtime.Stack on a hot path; capture the stack lazily (debug builds only) or use a pre-built constant",
            out,
        );
    }
}

/// PERF-159: `json.NewDecoder(r).Decode(&v)` where `r` is a
/// pre-buffered `*bytes.Buffer` or already-in-memory `[]byte`. For
/// pre-buffered data, `json.Unmarshal` is faster and allocation-free.
pub(crate) fn detect_perf_159(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("json.NewDecoder") {
        return;
    }
    if !source.contains(".Decode(") {
        return;
    }
    let _ = facts;

    for call in &facts.calls {
        if call.callee.as_ref() != "json.NewDecoder" {
            continue;
        }
        let first = call.arguments.first().map(|a| a.as_ref()).unwrap_or("");
        let prebuffered = first.contains("bytes.NewReader")
            || first.contains("bytes.NewBuffer")
            || first.contains("strings.NewReader")
            || first.contains("bytes.NewBuffer")
            || (first.contains("[]byte") && first.contains(","));
        if !prebuffered {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_159,
            file,
            line,
            col,
            "json.NewDecoder on pre-buffered data; use json.Unmarshal for []byte to avoid the reader allocation",
            out,
        );
    }
}

/// PERF-167: `wg.Add(N)` inside a `go func()` body. The `Add` call
/// must run before the goroutine starts; calling it inside the body
/// creates a race where `wg.Wait` can return before the add is
/// observed, and the goroutine itself is wasted on the off chance
/// `Add` is missed.
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
        let window = &source[window_start..call.start_byte];
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

/// PERF-169: `atomic.Value.Store` / `atomic.Pointer.Store` called
/// inside a loop. `atomic.Value.Store` boxes the new value into an
/// `eface` (allocation) on every call. For frequent updates, prefer
/// `atomic.Pointer[T]` (Go 1.19+) which stores the pointer without
/// boxing.
pub(crate) fn detect_perf_169(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        // Match `x.Store` and `atomic.Value.Store` shapes.
        if !callee.ends_with(".Store") {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        // The detector should only fire when the file uses
        // `sync/atomic` (otherwise `.Store` could be on a map,
        // channel, etc., which are different rules).
        if !facts.source_index.has("sync/atomic") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_169,
            file,
            line,
            col,
            "atomic.Value.Store inside a loop allocates an interface{} per call; use atomic.Pointer[T] (Go 1.19+) for frequent updates",
            out,
        );
        return;
    }
}

/// PERF-173: `time.Tick` without a paired `ticker.Stop()`. `time.Tick`
/// returns a ticker that cannot be stopped, so the underlying
/// goroutine leaks for the lifetime of the program. The detector
/// fires when the call is *bound* to a variable (i.e. used more
/// than once) so the call could have been `NewTicker`. A bare
/// `for range time.Tick(...)` is suppressed because the user
/// has no way to call Stop on it.
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
        let pre = &source[pre_start..call.start_byte];
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
    let _ = facts;
}

/// PERF-174: receiver side `close(ch)` on a channel. Only the
/// sender should close a channel; the receiver must not close it.
/// The detector fires when the *same function* both receives on
/// the channel and closes it.
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
        let func_start = source[..call.start_byte]
            .rfind("func ")
            .unwrap_or(0);
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

/// PERF-175: spinning on a buffered channel receive. Detect
/// `for { x := <-ch }` (or `for x := range ch` on a buffered
/// channel) without any yield / select / condition. The loop
/// burns CPU when the channel is empty.
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
        let body_window = &source[start..(start + 1024).min(source.len())];
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

/// PERF-178: `time.Format` repeated more than once on the same
/// value inside a single function. `time.AppendFormat` writes into
/// a caller-provided buffer and avoids allocating a fresh string
/// per call.
pub(crate) fn detect_perf_178(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut formats: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref().ends_with(".Format") && !c.callee.as_ref().ends_with("AppendFormat"))
        .collect();
    if formats.len() < 2 {
        return;
    }
    formats.sort_by_key(|c| c.start_byte);
    for pair in formats.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.callee.as_ref() != b.callee.as_ref() {
            continue;
        }
        if b.start_byte - a.start_byte > 1024 {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_178,
            file,
            line,
            col,
            "time.Format called repeatedly with the same format string; use time.AppendFormat to write into a pooled buffer",
            out,
        );
        return;
    }
}

/// PERF-179: two or more `strings.Replace` calls with the same
/// `old, new` pair inside a function. `strings.Replacer` compiles
/// the substitution into a trie and is significantly faster for
/// repeated substitutions.
pub(crate) fn detect_perf_179(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("strings.Replace(") {
        return;
    }

    let mut replace_args: Vec<(&str, &str, usize)> = Vec::new();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Replace" {
            continue;
        }
        if call.arguments.len() < 3 {
            continue;
        }
        let old = call.arguments[1].as_ref();
        let new = call.arguments[2].as_ref();
        // Normalize: a quoted string is treated as a single token.
        let key = format!("{old}\u{1}{new}");
        replace_args.push((old, Box::leak(key.into_boxed_str()), call.start_byte));
    }
    // The boxed strings above leak; drop them before the function exits.
    if replace_args.len() < 2 {
        return;
    }
    // We only need the keys, so re-collect into a stable form.
    let mut keys: Vec<(String, usize)> = Vec::new();
    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Replace" {
            continue;
        }
        if call.arguments.len() < 3 {
            continue;
        }
        let key = format!(
            "{}\u{1}{}",
            call.arguments[1].as_ref(),
            call.arguments[2].as_ref()
        );
        keys.push((key, call.start_byte));
    }
    keys.sort_by_key(|(_, b)| *b);
    for pair in keys.windows(2) {
        if pair[0].0 != pair[1].0 {
            continue;
        }
        if pair[1].1 - pair[0].1 > 2048 {
            continue;
        }
        let (line, col) = unit.line_col(pair[0].1);
        emit::push_finding(
            &META_PERF_179,
            file,
            line,
            col,
            "strings.Replace with the same old/new pair called repeatedly; build a strings.Replacer once and reuse it",
            out,
        );
        return;
    }
    let _ = replace_args;
}

/// PERF-180: `csv.NewReader(...).Read()` called inside a `for`
/// loop. Each `Read` allocates a fresh `[]string` and (for the
/// default reader) reads one record at a time from the underlying
/// `io.Reader`. For bulk parsing, switch to `ReadAll` or a
/// streaming reader outside the loop.
pub(crate) fn detect_perf_180(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("csv.NewReader") {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        // Match any `.Read(` method call on a `csv.Reader`.
        // The walker records the full selector expression
        // (e.g. `r.Read`), so we accept any caller whose name
        // ends in `.Read`.
        if !callee.ends_with(".Read") {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_180,
            file,
            line,
            col,
            "csv.Reader.Read called inside a loop; reuse a single reader and consider ReadAll for bulk parsing",
            out,
        );
        return;
    }
}

/// PERF-183: `context.WithTimeout` / `context.WithDeadline` /
/// `context.WithCancel` inside a loop body. Each call allocates a
/// new context, a new cancel function, and registers a timer
/// (for timeouts); the entire stack must be cleaned up by defer.
/// `context.WithValue` is excluded — it is the safe alternative
/// the rule recommends.
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

/// PERF-184: `mime.TypeByExtension` in a hot path. The call walks
/// the system mime.types table on every invocation; cache the
/// result for the small set of extensions you actually use.
pub(crate) fn detect_perf_184(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "mime.TypeByExtension" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_184,
            file,
            line,
            col,
            "mime.TypeByExtension walks the mime.types table; cache the result for the extensions you handle",
            out,
        );
    }
}

/// PERF-185: `http.DetectContentType` inside a request handler. The
/// function inspects the first 512 bytes of the body and allocates
/// a fresh string; for known content types, parse the request
/// header instead.
pub(crate) fn detect_perf_185(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "http.DetectContentType" {
            continue;
        }
        if !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_185,
            file,
            line,
            col,
            "http.DetectContentType in a request handler; parse the Content-Type header or cache the result for the bodies you serve",
            out,
        );
    }
}

/// PERF-186: `strings.Fields` in a hot parsing path. `strings.Fields`
/// allocates a `[]string` of all whitespace-separated tokens; for
/// per-line processing, prefer `strings.Split` (or `strings.IndexByte`
/// + slicing) so each token avoids an extra copy.
pub(crate) fn detect_perf_186(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "strings.Fields" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let _ = facts;
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_186,
            file,
            line,
            col,
            "strings.Fields in a hot path; use strings.IndexByte to walk whitespace and slice once per token",
            out,
        );
    }
}

/// PERF-187: `template.HTMLEscaper` in a hot path. The function is
/// the safe fallback; if you can guarantee the input is plain
/// text, use `template.HTML` (a typed alias) to skip the escape
/// step.
pub(crate) fn detect_perf_187(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "template.HTMLEscaper" && call.callee.as_ref() != "HTMLEscaper" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let _ = facts;
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_187,
            file,
            line,
            col,
            "template.HTMLEscaper in a hot path; pre-escape at write time or use template.HTML when the input is trusted",
            out,
        );
    }
}

/// PERF-188: `fmt.Sscanf` in a hot path. `fmt.Sscanf` uses
/// reflection to walk the format string and is ~10x slower than a
/// hand-rolled parser; use `strconv.Parse*` for the common
/// conversions.
pub(crate) fn detect_perf_188(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "fmt.Sscanf" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let _ = facts;
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_188,
            file,
            line,
            col,
            "fmt.Sscanf in a hot path; use strconv.ParseInt / strconv.ParseFloat for the common conversions",
            out,
        );
    }
}

/// PERF-193: `t.Reset(...)` not called in a loop that uses the
/// same `*time.Timer`. Forgetting to reset the timer causes
/// `time.After` to allocate a fresh timer per iteration.
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
        let window = &source[call.start_byte..(call.start_byte + 1024).min(source.len())];
        if window.contains(".Reset(") {
            continue;
        }
        let _ = facts;
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

/// PERF-194: `time.Sleep` in a request handler as a polling
/// primitive. Polling with `time.Sleep` is wasteful — use a
/// ticker or wait for a channel / condition variable instead.
pub(crate) fn detect_perf_194(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "time.Sleep" {
            continue;
        }
        if !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let _ = facts;
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

/// PERF-202: `json.MarshalIndent` / `json.Encoder.SetIndent` in a
/// production handler. Indented JSON is ~2x larger and slower
/// than compact JSON; only use it for tooling output.
pub(crate) fn detect_perf_202(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee == "json.MarshalIndent" {
            if !is_handler_shaped(&unit.source, call.start_byte) {
                continue;
            }
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_202,
                file,
                line,
                col,
                "json.MarshalIndent in a request handler; use json.Marshal for compact output in production",
                out,
            );
            continue;
        }
        if callee.ends_with(".SetIndent") {
            if !is_handler_shaped(&unit.source, call.start_byte) {
                continue;
            }
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_202,
                file,
                line,
                col,
                "json.Encoder.SetIndent in a request handler; indentation doubles the response size and slows down marshalling",
                out,
            );
        }
    }
    let _ = facts;
}

/// PERF-207: Fiber `c.SendFile(...)` without a `c.Set("Cache-Control", ...)`
/// or `c.Set("ETag", ...)` call in the same handler. Each request
/// re-reads the file from disk and re-transmits the bytes.
pub(crate) fn detect_perf_207(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("c.SendFile(") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "c.SendFile" && call.callee.as_ref() != "SendFile" {
            continue;
        }
        if !is_handler_shaped(source, call.start_byte) {
            continue;
        }
        // The 1 KiB window around the call must NOT contain a
        // Cache-Control / ETag / Last-Modified set.
        let window = &source[call.start_byte.saturating_sub(512)..(call.start_byte + 512).min(source.len())];
        if window.contains("Cache-Control")
            || window.contains("ETag")
            || window.contains("Last-Modified")
            || window.contains("CacheControl")
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_207,
            file,
            line,
            col,
            "c.SendFile without Cache-Control / ETag / Last-Modified headers; set cache headers to allow downstream caching",
            out,
        );
    }
}

/// PERF-210: `rdb.Keys(...)` or `client.Keys(...)` in a request
/// handler. `KEYS` scans the entire keyspace; use `SCAN` for
/// incremental iteration.
pub(crate) fn detect_perf_210(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Keys") && callee != "Keys" {
            continue;
        }
        if !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
        let _ = facts;
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_210,
            file,
            line,
            col,
            "redis KEYS command in a request handler; use SCAN for incremental iteration to avoid blocking the Redis server",
            out,
        );
    }
}

/// PERF-212: `db.Find(&slice)` (or `db.Model(...).Find(...)`)
/// without a `.Limit(...)` call in the same statement. For tables
/// that grow unbounded, this loads the entire table into memory.
/// The detector suppresses when the call is preceded by
/// `.Preload(`, `.Joins(`, or other modifiers that already
/// signal the developer is aware of the query shape.
pub(crate) fn detect_perf_212(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee != "db.Find" && !callee.ends_with(".Find") {
            continue;
        }
        let Some(first) = call.arguments.first().map(|a| a.as_ref()) else {
            continue;
        };
        let trimmed = first.trim_start();
        if !trimmed.starts_with('&') {
            continue;
        }
        let after_amp = trimmed.trim_start_matches('&').trim();
        let ident = after_amp
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        if ident.is_empty() {
            continue;
        }
        // The variable must be a slice.
        let decls = [
            format!("var {ident} []"),
            format!("{ident} := []"),
            format!("{ident} := make([]"),
        ];
        if !decls.iter().any(|d| source.contains(d.as_str())) {
            continue;
        }
        // The statement must not contain a `.Limit(`, `.Preload(`,
        // `.Joins(`, `.Select(`, or `.Where(` between the start
        // of the statement and the call itself. These modifiers
        // signal that the developer is shaping the query.
        let stmt_start = source[..call.start_byte]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let stmt = &source[stmt_start..call.start_byte];
        // The chain itself is part of the call's callee text. The
        // walker records the start of the chain (e.g.
        // `db.Preload(...).Find`), so the modifiers live in the
        // callee, not the stmt.
        let chain = callee;
        let combined = format!("{stmt}{chain}");
        if combined.contains("Limit(")
            || combined.contains("Preload(")
            || combined.contains("Joins(")
            || combined.contains("Select(")
            || combined.contains("Where(")
            || combined.contains("Not(")
            || combined.contains("Order(")
            || combined.contains("Group(")
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_212,
            file,
            line,
            col,
            "db.Find(&slice) without a preceding .Limit; bound the result set on tables that can grow unbounded",
            out,
        );
    }
    let _ = facts;
}

/// Coarse handler-shape check used by the request-path rules
/// above. The caller passes the call-site byte offset; we look
/// back at most 1 KiB for one of the standard handler-context
/// parameter tokens.
fn is_handler_shaped(source: &str, start_byte: usize) -> bool {
    let window_start = start_byte.saturating_sub(1024);
    let window = &source[window_start..start_byte];
    window.contains("http.ResponseWriter")
        || window.contains("*gin.Context")
        || window.contains("gin.Context")
        || window.contains("echo.Context")
        || window.contains("c echo.Context")
        || window.contains("*fiber.Ctx")
        || window.contains("c *fiber.Ctx")
        || window.contains("func Handle")
        || window.contains("func (")
        || window.contains("c.JSON(")
        || window.contains("c.String(")
        || window.contains("c.HTML(")
}

/// Whole-file handler-shape check used by detectors that
/// don't have a specific call-site byte offset. Returns true
/// when the file contains a request-handler signature token
/// anywhere.
fn file_has_handler(source: &str) -> bool {
    is_handler_shaped(source, source.len())
}

// ---------------------------------------------------------------------------
// Batch 2 detectors
// ---------------------------------------------------------------------------

/// PERF-109: `m[fmt.Sprintf(...)]` or `m[fn(x)]` inside a `for`
/// loop, where the function argument doesn't change per iteration.
/// Cache the key once and reuse it.
pub(crate) fn detect_perf_109(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for ") {
        return;
    }

    for (start, _end) in &facts.for_ranges {
        let range_text = &source[*start..(*start + 1024).min(source.len())];
        // Look for an expensive key computation inside the
        // loop body. The marker must be followed by use as a
        // map index in the same loop body.
        for marker in &["fmt.Sprintf(", "strings.Join(", "strings.ToLower(", "strings.ToUpper("] {
            if !range_text.contains(marker) {
                continue;
            }
            // The marker call is inside the loop body, and the
            // loop body has a map index (e.g. `m[key]` or
            // `out[key]++`). This is a smell: the key is being
            // recomputed per iteration.
            if range_text.contains("[") && range_text.contains("]") {
                let (line, col) = unit.line_col(*start);
                emit::push_finding(
                    &META_PERF_109,
                    file,
                    line,
                    col,
                    "expensive key computation inside the loop; cache the result before the loop",
                    out,
                );
                return;
            }
        }
    }
}

/// PERF-142: `r.Body` (or `c.Request.Body`) read in a handler
/// without `http.MaxBytesReader` wrapping. A malicious client can
/// send unbounded data; the wrapper limits the body to a configured
/// maximum. The detector fires when the body is actually read
/// via `io.ReadAll` (or `ioutil.ReadAll`).
pub(crate) fn detect_perf_142(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if source.contains("MaxBytesReader") {
        return;
    }
    let body_reads = [
        ("io.ReadAll(", "r.Body"),
        ("io.ReadAll(", "c.Request.Body"),
        ("io.ReadAll(", "req.Body"),
        ("io.ReadAll(", "ctx.Request.Body"),
        ("ioutil.ReadAll(", "r.Body"),
        ("ioutil.ReadAll(", "c.Request.Body"),
    ];
    let mut found_pos: Option<usize> = None;
    for (func, body) in body_reads.iter() {
        if source.contains(func) && source.contains(body) {
            found_pos = Some(source.find(func).unwrap_or(0));
            break;
        }
    }
    let Some(pos) = found_pos else {
        return;
    };

    let (line, col) = unit.line_col(pos);
    emit::push_finding(
        &META_PERF_142,
        file,
        line,
        col,
        "request body is read without http.MaxBytesReader; cap the body size to prevent OOM",
        out,
    );
}

/// PERF-144: `w.Write(...)` is called without a preceding
/// `w.Header().Set("Content-Length", ...)` for handlers that
/// configure other headers (suggesting the developer is shaping
/// the response). Without Content-Length, Go uses chunked
/// encoding which adds per-chunk overhead.
pub(crate) fn detect_perf_144(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains("w.Write(") {
        return;
    }
    if source.contains("Content-Length") {
        return;
    }
    // Suppress when the handler doesn't configure any headers —
    // small response handlers often rely on Go's automatic
    // Content-Length for short bodies.
    if !source.contains("w.Header().Set(") {
        return;
    }

    // The finding points at the first w.Write call.
    let Some(pos) = source.find("w.Write(") else {
        return;
    };
    let (line, col) = unit.line_col(pos);
    emit::push_finding(
        &META_PERF_144,
        file,
        line,
        col,
        "w.Write without setting Content-Length; set the header to enable connection reuse and avoid chunked encoding",
        out,
    );
}

/// PERF-148: `ch <- value` sent on an unbuffered channel that has
/// no matching receive in the same function. If the receiver is in
/// a different goroutine and exits early, the sender blocks
/// forever.
pub(crate) fn detect_perf_148(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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
            .find(|c: char| c == '\n' || c == ';')
            .map(|i| start + i)
            .unwrap_or(source.len());
        let make_stmt = &source[start..stmt_end];
        let is_unbuffered = if make_stmt.contains(", ") {
            let after = &make_stmt[make_stmt.rfind(", ").unwrap() + 2..];
            let cap_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
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
    let _ = facts;
}

/// PERF-152: `for k, v := range src` followed by `dst.Set(k, v)`
/// in a handler. Use `http.Header.Clone()` to shallow-copy in
/// bulk.
pub(crate) fn detect_perf_152(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for ") {
        return;
    }
    if !source.contains(".Set(") {
        return;
    }
    // The detector requires the file to mention Header so the
    // pattern is clearly a header copy.
    if !source.contains("Header") && !source.contains("header") {
        return;
    }

    for (start, _end) in &facts.for_ranges {
        let range_text = &source[*start..(*start + 512).min(source.len())];
        if !range_text.contains("range ") {
            continue;
        }
        if !range_text.contains(".Set(") {
            continue;
        }
        let (line, col) = unit.line_col(*start);
        emit::push_finding(
            &META_PERF_152,
            file,
            line,
            col,
            "header copy via for-range and .Set; use http.Header.Clone() for the common header forwarding pattern",
            out,
        );
        return;
    }
}

/// PERF-153: `cookie.String()` called more than once for the
/// same cookie in a handler. The method re-serializes the cookie
/// each call.
pub(crate) fn detect_perf_153(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut strings: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref().ends_with(".String"))
        .collect();
    if strings.len() < 2 {
        return;
    }
    strings.sort_by_key(|c| c.start_byte);
    for pair in strings.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.callee.as_ref() != b.callee.as_ref() {
            continue;
        }
        if b.start_byte - a.start_byte > 1024 {
            continue;
        }
        // The receiver must look like a cookie variable.
        if !a.callee.as_ref().to_lowercase().contains("cookie") {
            continue;
        }
        let (line, col) = unit.line_col(a.start_byte);
        emit::push_finding(
            &META_PERF_153,
            file,
            line,
            col,
            "Cookie.String called repeatedly; cache the serialized cookie or extract only the needed field",
            out,
        );
        return;
    }
}

/// PERF-154: `http.HandlerFunc(someFunc)` where `someFunc` is
/// already an `http.HandlerFunc`. The conversion is a no-op.
pub(crate) fn detect_perf_154(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("http.HandlerFunc(") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "http.HandlerFunc" {
            continue;
        }
        let Some(first) = call.arguments.first().map(|a| a.as_ref()) else {
            continue;
        };
        // Suppress when the argument is a function literal
        // (it isn't a real conversion).
        if first.contains("func(") || first.contains("func (") {
            continue;
        }
        // Suppress when the argument is a generic identifier
        // (we can't tell if it's already a HandlerFunc).
        if first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            // The detector accepts single-identifier args as
            // potential conversions. The flag is "consider
            // removing the explicit cast".
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_154,
                file,
                line,
                col,
                "explicit http.HandlerFunc conversion may be redundant; pass the function directly to http.HandleFunc",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-160: `sql.Open` called inside a request handler. A new
/// connection pool per invocation bypasses pool tuning and leaks
/// idle connections under load.
pub(crate) fn detect_perf_160(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains("sql.Open(") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "sql.Open" {
            continue;
        }
        // A `var db = sql.Open(...)` at package scope is fine.
        // The detector fires only on calls inside a function
        // (i.e. the call is not preceded by `var ` at the
        // package level). Approximate by checking the 16 bytes
        // before the call.
        let pre_start = call.start_byte.saturating_sub(16);
        let pre = &source[pre_start..call.start_byte];
        if pre.contains("var ") && !pre.contains("func ") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_160,
            file,
            line,
            col,
            "sql.Open in a request handler; open the *sql.DB once at startup and reuse it across requests",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-162: `db.Ping` (or `db.PingContext`) called inside a
/// request handler. Each ping adds a round-trip per inbound call.
pub(crate) fn detect_perf_162(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains(".Ping(") && !source.contains(".PingContext(") {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee != "db.Ping" && callee != "db.PingContext" && !callee.ends_with(".Ping")
            && !callee.ends_with(".PingContext")
        {
            continue;
        }
        // The call must not be in a health-check function. We
        // approximate by looking at the 64 bytes before the
        // call for `func Health` or `func (h *Health`.
        let pre_start = call.start_byte.saturating_sub(256);
        let pre = &source[pre_start..call.start_byte];
        if pre.contains("func Health") || pre.contains("func (h *Health") || pre.contains("func Healthz") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_162,
            file,
            line,
            col,
            "db.Ping in a request handler; add a dedicated health-check endpoint or a periodic background ping instead",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-164: `db.Query` / `db.Exec` (non-Context) called inside a
/// request handler. Use `db.QueryContext` / `db.ExecContext` to
/// propagate cancellation and request-level timeouts. The
/// detector only fires when the handler has a request context
/// available (otherwise the non-Context variant is the only
/// option).
pub(crate) fn detect_perf_164(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    // The handler must have a request variable in scope. We
    // accept the function parameter (`r *http.Request`) as a
    // signal that the developer should pass it to the
    // Context-aware db method.
    let has_request_var = source.contains("r *http.Request")
        || source.contains("r.Context()")
        || source.contains("req.Context()")
        || source.contains("r.Header")
        || source.contains("r.URL")
        || source.contains("r.Method")
        || source.contains("r.Body")
        || source.contains("c.Request.Context()")
        || source.contains("ctx.Request.Context()")
        || source.contains("c.Request.Body");
    if !has_request_var {
        return;
    }

    let triggers = [
        "db.Query(",
        "db.Exec(",
        "db.Prepare(",
        "db.Begin(",
    ];
    if !triggers.iter().any(|t| source.contains(t)) {
        return;
    }

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(callee, "db.Query" | "db.Exec" | "db.Prepare" | "db.Begin") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_164,
            file,
            line,
            col,
            "db.* call without Context in a request handler; use the Context variant for cancellation propagation",
            out,
        );
    }
    let _ = facts;
}

/// PERF-189: HTTP response body is closed without first being
/// drained to `io.Discard`. The connection can be reused for
/// keep-alive only when the body has been fully read.
pub(crate) fn detect_perf_189(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("io.Copy(io.Discard,") {
        // We only fire when the file uses io.Copy(io.Discard, ...)
        // — this is the canonical "drain" pattern. Files that
        // don't drain at all are picked up by PERF-103.
        return;
    }

    // Find every (drain, close) pair. The drain must come BEFORE
    // the close for the same response. When drain_pos > close_pos
    // the body is closed before being drained — the connection
    // can't be reused.
    let drain_pos = source.find("io.Copy(io.Discard,").unwrap_or(0);
    let close_pos = source.find(".Body.Close()").unwrap_or(0);
    if close_pos > 0 && close_pos < drain_pos {
        let (line, col) = unit.line_col(close_pos);
        emit::push_finding(
            &META_PERF_189,
            file,
            line,
            col,
            "Body.Close called before io.Copy(io.Discard, body); drain BEFORE close to allow keep-alive connection reuse",
            out,
        );
    }
    let _ = facts;
}

/// PERF-191: `[]*SmallStruct` slice declared but the struct has
/// very few fields. Pointers add 8 bytes per element + an extra
/// heap allocation per element.
pub(crate) fn detect_perf_191(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Suppress when the file uses protobuf or similar
    // frameworks that prefer pointer types.
    if source.contains("proto.") || source.contains("protobuf") {
        return;
    }

    // Heuristic: a slice literal or declaration of `[]*T` where
    // the type T is declared with 1 or 2 fields.
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find("[]*") {
        let pos = search_from + rel;
        let after = &source[pos + 3..(pos + 128).min(source.len())];
        let type_name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if type_name.is_empty() {
            search_from = pos + 3;
            continue;
        }
        let pattern = format!("type {type_name} struct");
        if let Some(struct_start) = source.find(&pattern) {
            if let Some(open) = source[struct_start..].find('{') {
                let body_start = struct_start + open + 1;
                if let Some(close_rel) = source[body_start..].find('}') {
                    let body = &source[body_start..body_start + close_rel];
                    let field_count = body
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| {
                            !l.is_empty()
                                && !l.starts_with("//")
                                && !l.starts_with('{')
                                && !l.starts_with('}')
                                && !l.starts_with('`')
                        })
                        .count();
                    if field_count > 0 && field_count <= 2 {
                        let (line, col) = unit.line_col(pos);
                        emit::push_finding(
                            &META_PERF_191,
                            file,
                            line,
                            col,
                            "slice of pointers to a small struct; use []T (value type) to avoid per-element heap allocations",
                            out,
                        );
                        return;
                    }
                }
            }
        }
        search_from = pos + 3;
    }
}

/// PERF-197: multiple `io.ReadAll(c.Request.Body)` (or similar)
/// calls in the same handler. The body can be read only once; a
/// second ReadAll returns EOF.
pub(crate) fn detect_perf_197(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut reads: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "io.ReadAll" || c.callee.as_ref() == "ioutil.ReadAll")
        .collect();
    if reads.len() < 2 {
        return;
    }
    reads.sort_by_key(|c| c.start_byte);
    for pair in reads.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.arguments.is_empty() || b.arguments.is_empty() {
            continue;
        }
        let a_arg = a.arguments[0].as_ref();
        let b_arg = b.arguments[0].as_ref();
        if a_arg == b_arg && (a_arg.contains("Body") || a_arg.contains("body")) {
            let (line, col) = unit.line_col(b.start_byte);
            emit::push_finding(
                &META_PERF_197,
                file,
                line,
                col,
                "io.ReadAll(c.Request.Body) called twice; the second read returns EOF, cache the body or read into a buffer",
                out,
            );
            return;
        }
    }
}

/// PERF-203: `ip.String()` called more than once in a handler.
/// Each call allocates a new string; cache the result.
pub(crate) fn detect_perf_203(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let mut strings: Vec<&crate::lang::go::detectors::perf::facts::CallFact> = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref().ends_with(".String"))
        .collect();
    if strings.len() < 2 {
        return;
    }
    strings.sort_by_key(|c| c.start_byte);
    for pair in strings.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if a.callee.as_ref() != b.callee.as_ref() {
            continue;
        }
        if b.start_byte - a.start_byte > 1024 {
            continue;
        }
        // The receiver must look like an IP address variable.
        let callee = a.callee.as_ref();
        if callee.to_lowercase().contains("ip.") || callee.starts_with("ip.") {
            let (line, col) = unit.line_col(a.start_byte);
            emit::push_finding(
                &META_PERF_203,
                file,
                line,
                col,
                "ip.String() called repeatedly on the same IP; cache the result or write directly to a buffer",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-205: GORM `db.Count(&total)` (or `db.Model().Count`) followed by
/// `db.Offset(...).Limit(...).Find(&records)` in the same handler.
/// Keyset pagination avoids OFFSET degradation on large tables.
pub(crate) fn detect_perf_205(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_count = source.contains("db.Count(") || source.contains(".Count(&");
    if !has_count {
        return;
    }
    if !source.contains(".Offset(") {
        return;
    }
    if !source.contains(".Limit(") {
        return;
    }
    if !source.contains(".Find(") {
        return;
    }

    // Find the first `.Count(` and the first `.Find(`.
    let count_pos = source.find(".Count(").unwrap_or(0);
    let find_pos = source.find(".Find(").unwrap_or(0);
    if find_pos <= count_pos || count_pos == 0 {
        return;
    }
    if find_pos - count_pos > 2048 {
        return;
    }
    let (line, col) = unit.line_col(count_pos);
    emit::push_finding(
        &META_PERF_205,
        file,
        line,
        col,
        "db.Count + db.Offset.Limit.Find pattern; use keyset pagination (where id > last_id) for large tables",
        out,
    );
    let _ = facts;
}

/// PERF-206: `sqlx.Unsafe(...)` or `db.Unsafe()` used with a
/// runtime-built query string. Unsafe mode should only be used
/// with static queries. The detector fires when an `Unsafe()`
/// call appears in a chain that uses a non-literal query
/// argument (e.g. `db.Unsafe().Where(name + " = ?", id)`).
pub(crate) fn detect_perf_206(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let _ = facts;

    if !source.contains("Unsafe(") {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Where") && !callee.ends_with(".Find") && !callee.ends_with(".First") {
            continue;
        }
        let Some(first) = call.arguments.first().map(|a| a.as_ref()) else {
            continue;
        };
        if first.starts_with("\"") {
            continue;
        }
        if first.contains("+ \"")
            || first.contains("\" +")
            || first.contains("fmt.Sprintf(")
            || (!first.starts_with("\"") && first.contains('"'))
        {
            // The chain itself includes the Unsafe call.
            if callee.contains("Unsafe") {
                let (line, col) = unit.line_col(call.start_byte);
                emit::push_finding(
                    &META_PERF_206,
                    file,
                    line,
                    col,
                    "sqlx.Unsafe used with a non-literal query; use a static string for the query when in Unsafe mode",
                    out,
                );
                return;
            }
        }
    }
    let _ = source;
}

// ---------------------------------------------------------------------------
// Batch 3 detectors
// ---------------------------------------------------------------------------

/// PERF-143: route handlers that take a long time to respond
/// without `http.TimeoutHandler` wrapping. Per-route timeouts
/// allow different deadlines for fast endpoints vs slow ones.
pub(crate) fn detect_perf_143(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains("http.HandleFunc") && !source.contains("http.Handle(") {
        return;
    }
    if source.contains("http.TimeoutHandler") {
        return;
    }
    // The file uses http.Handle / http.HandleFunc without
    // wrapping in TimeoutHandler. We accept any handler
    // registration as a signal.
    let pos = source
        .find("http.HandleFunc")
        .or_else(|| source.find("http.Handle("))
        .unwrap_or(0);
    let (line, col) = unit.line_col(pos);
    emit::push_finding(
        &META_PERF_143,
        file,
        line,
        col,
        "handler registered without http.TimeoutHandler; wrap slow handlers in TimeoutHandler to enforce per-route deadlines",
        out,
    );
}

/// PERF-155: route handler that internally checks `r.Method` with
/// an `if` or `switch` statement instead of using method-aware
/// routing (Go 1.22+ mux or a method-restriction wrapper).
pub(crate) fn detect_perf_155(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains("r.Method") && !source.contains("req.Method") {
        return;
    }

    // The handler must have an `if r.Method ... {` or
    // `switch r.Method {` shape.
    for (start, _end) in &facts.for_ranges {
        let range_text = &source[*start..(*start + 1024).min(source.len())];
        if range_text.contains("r.Method") || range_text.contains("req.Method") {
            let _ = start;
        }
    }
    // Simpler approach: search the whole file for `r.Method`
    // followed by `if` or `switch` in a handler context.
    let has_method_branch = source.contains("if r.Method")
        || source.contains("switch r.Method")
        || source.contains("if req.Method")
        || source.contains("switch req.Method");
    if !has_method_branch {
        return;
    }
    // The pattern is the smell. We point at the first method check.
    let pos = source
        .find("r.Method")
        .or_else(|| source.find("req.Method"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(pos);
    emit::push_finding(
        &META_PERF_155,
        file,
        line,
        col,
        "handler checks r.Method internally; use Go 1.22+ method routing or a method-aware mux",
        out,
    );
    let _ = facts;
}

/// PERF-134: manual `for` + `Read` + `Write` loop instead of
/// `io.Copy`. The idiomatic `io.Copy(dst, src)` is a single call;
/// a manual loop re-implements the same logic and is more code to
/// audit.
pub(crate) fn detect_perf_134(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    if !source.contains("for ") {
        return;
    }
    // Look for a `for` block containing both `Read(buf)` and
    // `Write(buf[:` — the manual-copy idiom.
    if !source.contains(".Read(") || !source.contains(".Write(") {
        return;
    }
    // Simple presence: any `.Read(buf)` paired with `.Write(buf[:`
    // in a file with a `for` loop is almost certainly the manual
    // copy pattern. We use `buf` as the canonical variable name.
    if source.contains("Read(buf") && source.contains("Write(buf[:") {
        let pos = source.find("Read(buf").unwrap();
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_134,
            file,
            line,
            col,
            "manual io.Read + io.Write loop; use io.Copy(dst, src) instead",
            out,
        );
        return;
    }
    let _ = _facts;
}

/// PERF-139: closure escape — a closure in a hot path that captures
/// variables from the enclosing scope, causing heap allocation.
/// Detected by looking for `go func` or `defer func` in a handler
/// function that accesses outer variables.
pub(crate) fn detect_perf_139(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // A closure in a handler that captures outer scope variables
    // is the escape pattern. We look for `go func(` or `defer func(`
    // that accesses a local variable (not just its parameters).
    if !source.contains("go func(") && !source.contains("defer func(") {
        return;
    }
    // The closure must capture an outer variable: look for
    // `.Write` inside the closure body. We scan for `go func(`
    // or `defer func(` and check if `.Write(` appears between
    // the `{` that opens the closure body and the `})` that
    // closes it (or the next `)(` for defer func() calls).
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Write") {
            continue;
        }
        // Check if this Write is inside a closure by finding a
        // `go func(` that starts before it and whose matching
        // `})` comes after it.
        // Find the LAST `go func(` before the Write call
        let search_start = call.start_byte.saturating_sub(1000);
        let search_region = &source[search_start..call.start_byte];
        let last_go_rel = search_region.rfind("go func(");
        let last_defer_rel = search_region.rfind("defer func(");
        let closure_start_rel = match (last_go_rel, last_defer_rel) {
            (Some(g), Some(d)) => Some(g.max(d)),
            (Some(g), None) => Some(g),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        let Some(csr) = closure_start_rel else {
            continue;
        };
        // Convert relative offset to absolute source offset
        let cs = search_start + csr;
        // The closure body starts at the `{` after `go func()`
        // or `defer func()`. We find the next `{` after cs.
        // Look forward from cs for the first `{`.
        let after_closure_open = &source[cs..];
        let body_open = match after_closure_open.find('{') {
            Some(p) => cs + p,
            None => continue,
        };
        // Look for `})` or `}()` that closes this closure.
        let after_body = &source[body_open..];
        let close_pos = after_body.find("})")
            .or_else(|| after_body.find("}()"))
            .or_else(|| after_body.find("}"))
            .map(|p| body_open + p);
        let Some(cp) = close_pos else {
            continue;
        };
        // The Write call must be between body_open and cp
        if call.start_byte > body_open && call.start_byte < cp {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_139,
                file,
                line,
                col,
                "closure in hot-path handler captures outer variables; consider extracting to a named function",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-150: large stack frame from local variables. When a handler
/// allocates multiple large local buffers (byte arrays, structs,
/// strings), the goroutine stack frame grows and the allocation
/// cost shifts from the heap to the stack — but very large frames
/// cause cache pressure.
pub(crate) fn detect_perf_150(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // Heuristic: count large local allocations.
    // We look for `[N]byte` array declarations, `make([]byte,N)`
    // where N >= 1024, and lines with large string literals.
    let large_array = source.matches("[1024]byte").count()
        + source.matches("[2048]byte").count()
        + source.matches("[4096]byte").count()
        + source.matches("[8192]byte").count()
        + source.matches("[16384]byte").count();
    let make_big = source.matches("make([]byte, 4096)").count()
        + source.matches("make([]byte, 8192)").count()
        + source.matches("make([]byte, 1024)").count();
    let large_strings = source
        .lines()
        .filter(|l| l.len() > 200 && l.contains('"'))
        .count();

    let total = large_array + make_big + large_strings;
    if total >= 2 {
        let pos = source.find("]byte").unwrap_or_else(|| {
            source
                .find("make([]byte,")
                .unwrap_or(source.find('"').unwrap_or(0))
        });
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_150,
            file,
            line,
            col,
            "large stack frame: multiple large local allocations (> 1 KiB); consider heap-allocating or reducing buffer sizes",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-151: non-inlinable function on hot path. A request handler
/// that contains complex control flow (multiple loops, closures,
/// large bodies) cannot be inlined by the Go compiler, adding call
/// overhead to every request.
pub(crate) fn detect_perf_151(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) {
        return;
    }
    // Heuristic: a function that has both `for` AND `switch` AND
    // `defer func` is complex enough that the compiler won't inline
    // it. We also flag functions with > 40 source lines between
    // `func` and the matching `}`.
    let has_loop = source.contains("for ");
    let has_switch = source.contains("switch ");
    let has_closure = source.contains("func(") || source.contains("go ");

    // Count approximate lines in the first function body.
    let func_lines = source
        .lines()
        .skip_while(|l| !l.contains("func "))
        .take_while(|l| !l.trim().is_empty())
        .count();

    let complex = (has_loop && has_switch) || func_lines > 50;
    if complex && has_closure {
        let pos = source.find("func ").unwrap_or(0);
        let (line, col) = unit.line_col(pos);
        emit::push_finding(
            &META_PERF_151,
            file,
            line,
            col,
            "non-inlinable handler function: too complex for the Go compiler to inline; reduce body size or split into smaller functions",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-172: `wg.Wait` inside a request handler. The serving
/// goroutine blocks until the spawned goroutines complete,
/// effectively serializing the request. This detector only fires
/// when `wg.Wait()` is followed by a response write and there is
/// no context-cancellation pattern in scope.
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
    let window = &source[window_start..wait_pos];
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

/// PERF-196: JWT / session parsing on every request. Look for
/// a `jwt.Parse` / `jwt.ParseWithClaims` / `session.Get` /
/// `cookie.Get` call inside a request handler.
pub(crate) fn detect_perf_196(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    let triggers = [
        "jwt.Parse(",
        "jwt.ParseWithClaims(",
        "session.Get(",
        "sessions.Get(",
        "cookie.Get(",
    ];
    if !triggers.iter().any(|t| source.contains(t)) {
        return;
    }

    for trigger in &triggers {
        let Some(rel) = source.find(trigger) else {
            continue;
        };
        // Suppress if the call is in a Middleware / Auth
        // function (the call is wrapped in a function whose
        // name contains Middleware, Auth, or Session).
        let pre_start = rel.saturating_sub(512);
        let pre = &source[pre_start..rel];
        if pre.contains("func AuthMiddleware")
            || pre.contains("func SessionMiddleware")
            || pre.contains("func Middleware")
            || pre.contains("func (h *Handler)")
            || pre.contains("func Authenticate")
        {
            continue;
        }
        let (line, col) = unit.line_col(rel);
        emit::push_finding(
            &META_PERF_196,
            file,
            line,
            col,
            "session / JWT parse in a request handler; cache the parsed session for the duration of the request",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-199: `session.Get` / `cookie.Get` / `c.Cookie` / `rdb.Get`
/// on every individual route handler. The fix is to move the
/// session lookup into a middleware that sets the request context.
pub(crate) fn detect_perf_199(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_session_lookup = source.contains("session.Get(")
        || source.contains("sessions.Get(")
        || source.contains("c.Cookie(")
        || source.contains("r.Cookie(")
        || source.contains("cookie.Get(")
        || source.contains("rdb.Get(")
        || source.contains("redis.Get(");
    if !has_session_lookup {
        return;
    }
    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if source.contains(".Use(") || source.contains("Group.Use(") {
        return;
    }

    // Find the first session lookup call. The lookup is only
    // a finding when the enclosing function is a request
    // handler, which we approximate by checking the 1 KiB
    // before the call for a handler signature.
    let triggers = [
        "c.Cookie(",
        "r.Cookie(",
        "session.Get(",
        "sessions.Get(",
        "cookie.Get(",
        "rdb.Get(",
        "redis.Get(",
    ];
    for trigger in &triggers {
        if let Some(pos) = source.find(trigger) {
            if is_handler_shaped(source, pos) {
                // Suppress when the enclosing function is a
                // middleware. We approximate by looking for
                // `c.Next()` or a return type of `gin.HandlerFunc`
                // in the function signature.
                let func_start = source[..pos]
                    .rfind("func ")
                    .unwrap_or(0);
                let func_window_end = (pos + 1024).min(source.len());
                let func_window = &source[func_start..func_window_end];
                if func_window.contains("c.Next()")
                    || func_window.contains("gin.HandlerFunc")
                    || func_window.contains("Middleware")
                    || func_window.contains("AuthMiddleware")
                {
                    continue;
                }
                let (line, col) = unit.line_col(pos);
                emit::push_finding(
                    &META_PERF_199,
                    file,
                    line,
                    col,
                    "session lookup in a route handler; move the lookup to a middleware that sets the request context",
                    out,
                );
                return;
            }
        }
    }
    let _ = facts;
}

/// PERF-200: middleware ordering — authentication, body parsing,
/// or rate limiting placed BEFORE cheap early-reject middleware
/// (CORS preflight, cache check, request validation).
pub(crate) fn detect_perf_200(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains(".Use(") {
        return;
    }
    // The file registers middleware. Look for an ordering smell:
    // `Use(AuthMiddleware)` followed later by `Use(CORSMiddleware)`.
    let auth_pos = source
        .find("Auth")
        .or_else(|| source.find("auth."))
        .or_else(|| source.find("RequireAuth"))
        .or_else(|| source.find("Authenticate"))
        .or_else(|| source.find("JWT"))
        .or_else(|| source.find("RateLimit"));
    let cors_pos = source
        .find("CORS")
        .or_else(|| source.find("cors."))
        .or_else(|| source.find("Cache"));
    if let (Some(auth), Some(cors)) = (auth_pos, cors_pos) {
        if auth < cors {
            let (line, col) = unit.line_col(cors);
            emit::push_finding(
                &META_PERF_200,
                file,
                line,
                col,
                "expensive middleware (Auth) registered before cheap preflight (CORS); move CORS first to short-circuit preflight requests",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-201: custom CORS preflight handler. The Go ecosystem has
/// a `cors` package that handles preflight in O(1) per request;
/// a custom handler typically allocates headers per call.
pub(crate) fn detect_perf_201(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // The detector fires when a custom handler branches on
    // `r.Method == "OPTIONS"` and sets CORS headers manually.
    if !source.contains("OPTIONS") {
        return;
    }
    if !source.contains("Access-Control-") {
        return;
    }
    if source.contains("github.com/gin-contrib/cors") || source.contains("cors.New(") {
        return;
    }

    let pos = source.find("OPTIONS").unwrap_or(0);
    let (line, col) = unit.line_col(pos);
    emit::push_finding(
        &META_PERF_201,
        file,
        line,
        col,
        "custom CORS preflight handler; use a community package (cors, gin-contrib/cors) for the standard preflight",
        out,
    );
    let _ = facts;
}

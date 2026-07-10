//! Generic hot-path fan-out, bulk buffer sizing, builder bridges, and set shapes.
//!
//! These detectors match **stdlib shapes** only (no product-local API names).

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
        if !loop_text.contains(".Go(") {
            continue;
        }

        let body = enclosing_function_body(source, loop_start).unwrap_or(source);
        // Scope to errgroup: SetLimit is that API's concurrency control.
        if !uses_errgroup(body) || has_concurrency_bound(body) {
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

/// PERF-235: Intermediate `strings.Builder` bridged into a byte sink via `.String()`.
///
/// Shape: build with `strings.Builder`, then `WriteString(b.String())` /
/// `Write([]byte(b.String()))` / `append(dst, b.String()...)` instead of writing
/// into the destination buffer directly.
///
/// Does **not** flag returning `b.String()` from a pooled builder (that is reuse,
/// not a temporary bridge into another sink).
pub(crate) fn detect_perf_235(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();
    if !source.contains("strings.Builder") {
        return;
    }

    let mut search = 0usize;
    while let Some(rel) = source[search..].find(".String()") {
        let start = search + rel;
        let body = enclosing_function_body(source, start).unwrap_or(source);
        if !body.contains("strings.Builder") {
            search = start + 8;
            continue;
        }
        if is_string_bridged_into_sink(source, start) {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_235,
                file,
                line,
                col,
                "temporary strings.Builder is flushed through .String() into a sink; write into the destination buffer directly",
                out,
            );
            return;
        }
        search = start + 8;
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

/// PERF-237: errgroup always fans out with no serial short-circuit for tiny N.
///
/// Distinct from PERF-232 (missing SetLimit) and PERF-228 (static 1–2 element
/// composite). Dynamic worksets of length 1–2 often cost more to schedule than
/// to run serially.
pub(crate) fn detect_perf_237(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();

    for &(loop_start, loop_end) in &facts.for_ranges {
        let end = loop_end.min(source.len()).max(loop_start);
        let loop_text = &source[loop_start..end];
        if !loop_text.contains(".Go(") {
            continue;
        }
        let body = enclosing_function_body(source, loop_start).unwrap_or(source);
        if !uses_errgroup(body) {
            continue;
        }
        // Dynamic range target preferred (not only composite literals — those are PERF-228).
        if !loop_text.contains(" range ") {
            continue;
        }
        if has_serial_short_circuit_near(source, loop_start) {
            continue;
        }

        let (line, col) = unit.line_col(loop_start);
        emit::push_finding(
            &META_PERF_237,
            file,
            line,
            col,
            "errgroup fan-out has no serial short-circuit for tiny worksets; run len(items) <= 2 serially before spawning",
            out,
        );
        return;
    }
}

/// PERF-238: BMP-ish membership tracked with `map[rune]bool` on a hot loop path.
pub(crate) fn detect_perf_238(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();
    if !source.contains("map[rune]bool") {
        return;
    }

    for &(loop_start, loop_end) in &facts.for_ranges {
        let end = loop_end.min(source.len()).max(loop_start);
        let loop_text = &source[loop_start..end];
        // Typical: seen[r] = true / set[char] = true
        if !(loop_text.contains("] = true")
            || loop_text.contains("]= true")
            || loop_text.contains("]=true")
            || loop_text.contains("] =true"))
        {
            continue;
        }
        // Require the map type nearby in the same function (not some other map).
        let body = enclosing_function_body(source, loop_start).unwrap_or(source);
        if !body.contains("map[rune]bool") && !source.contains("map[rune]bool") {
            continue;
        }

        let (line, col) = unit.line_col(loop_start);
        emit::push_finding(
            &META_PERF_238,
            file,
            line,
            col,
            "rune membership is updated via map[rune]bool in a loop; prefer a bitset or denser set when the domain is bounded (e.g. BMP)",
            out,
        );
        return;
    }
}

fn uses_errgroup(body: &str) -> bool {
    body.contains("errgroup.Group")
        || body.contains("errgroup.WithContext")
        || body.contains("errgroup.")
}

fn has_concurrency_bound(body: &str) -> bool {
    body.contains("SetLimit(")
        || body.contains("semaphore")
        || body.contains("sem.Acquire(")
        || body.contains("Acquire(ctx")
}

/// Serial short-circuit for tiny dynamic worksets (portable patterns only).
fn has_serial_short_circuit_near(source: &str, loop_start: usize) -> bool {
    let window_start = loop_start.saturating_sub(600);
    let window = &source[window_start..loop_start];
    const NEEDLES: &[&str] = &[
        "<= 2",
        "<=2",
        "< 2",
        "<2",
        "< 3",
        "<3",
        "== 1",
        "==1",
        "<= 1",
        "<=1",
    ];
    // Require a len(...) check near the threshold so we do not match unrelated `<= 2`.
    if !window.contains("len(") {
        return false;
    }
    NEEDLES.iter().any(|n| window.contains(n))
}

/// True when `.String()` is an argument to WriteString / []byte / append — not a
/// bare `return b.String()` or assignment used with a pooled builder.
fn is_string_bridged_into_sink(source: &str, string_dot: usize) -> bool {
    let before = &source[string_dot.saturating_sub(96)..string_dot];
    for needle in ["WriteString(", "WriteString (", "[]byte(", "append(", "append ("] {
        let Some(pos) = before.rfind(needle) else {
            continue;
        };
        let between = before[pos + needle.len()..].trim();
        // WriteString(sb.String()) → between == "sb"
        if is_simple_ident(between) {
            return true;
        }
        // append(dst, sb.String()...) → between == "dst, sb"
        if needle.starts_with("append") {
            if let Some(last) = between.rsplit(',').next() {
                if is_simple_ident(last.trim()) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_simple_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// PERF-239: Dense integer-keyed map filled with many index writes in one function.
///
/// Prefer a slice (or append-only records + one index pass) when keys are dense
/// integers written repeatedly. Distinct from PERF-221's sequential-key heuristic.
pub(crate) fn detect_perf_239(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();
    if !source.contains("map[int]") && !source.contains("map[int64]") {
        return;
    }

    // mapName := make(map[int]… or mapName := make(map[int64]…
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("make(map[int") {
        let make_at = search + rel;
        let head = &source[..make_at];
        // Walk back to find "name :=" or "name ="
        let Some(name) = map_name_before_make(head) else {
            search = make_at + 4;
            continue;
        };
        let body = enclosing_function_body(source, make_at).unwrap_or(source);
        let needle = format!("{name}[");
        let assigns = body.matches(needle.as_str()).count();
        if assigns >= 6 {
            let rel_assign = body.find(needle.as_str()).unwrap_or(0);
            // Approximate absolute: find first name[ after make_at in source
            let abs = source[make_at..]
                .find(needle.as_str())
                .map(|r| make_at + r)
                .unwrap_or(make_at);
            let _ = rel_assign;
            let (line, col) = unit.line_col(abs);
            emit::push_finding(
                &META_PERF_239,
                file,
                line,
                col,
                "dense integer-keyed map is written many times in one function; prefer a slice or append-only records with one final index",
                out,
            );
            return;
        }
        search = make_at + 4;
    }
}

/// PERF-240: Large byte scratch allocated from `len(src)` without pool reuse.
pub(crate) fn detect_perf_240(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();

    let mut search = 0usize;
    while let Some(rel) = source[search..].find("make([]byte") {
        let start = search + rel;
        let after = &source[start..char_boundary_local(source, start + 80)];
        // make([]byte, len(x)) or make([]byte, 0, len(x)) — sized from another buffer
        if !after.contains("len(") {
            search = start + 4;
            continue;
        }
        let body = enclosing_function_body(source, start).unwrap_or(source);
        // Suppress when the function clearly pools scratch.
        if body.contains("sync.Pool")
            || body.contains("Pool.Get")
            || body.contains("scratchPool")
            || body.contains("bufPool")
        {
            search = start + 4;
            continue;
        }
        // Hot: inside a loop, or encode/build/subset/process-style function.
        let in_loop = facts
            .for_ranges
            .iter()
            .any(|&(a, b)| start >= a && start < b);
        let fname = enclosing_function_name(source, start)
            .unwrap_or("")
            .to_ascii_lowercase();
        let hot_name = fname.contains("encode")
            || fname.contains("build")
            || fname.contains("subset")
            || fname.contains("process")
            || fname.contains("render")
            || fname.contains("compress")
            || fname.contains("write")
            || fname.contains("generate");
        if !in_loop && !hot_name {
            search = start + 4;
            continue;
        }
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_240,
            file,
            line,
            col,
            "large []byte scratch is allocated from len(source) without pool reuse; pool and reset a scratch buffer on hot paths",
            out,
        );
        return;
    }
}

/// PERF-241: ASN.1 (re)marshal with fresh time.Now on a signing path.
pub(crate) fn detect_perf_241(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();
    if !(source.contains("asn1.Marshal") && source.contains("time.Now")) {
        return;
    }

    // Prefer sign-named functions; also accept Marshal near time.Now in same body.
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("asn1.Marshal") {
        let start = search + rel;
        let fname = enclosing_function_name(source, start)
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = enclosing_function_body(source, start).unwrap_or("");
        let signish = fname.contains("sign")
            || fname.contains("signature")
            || fname.contains("pkcs")
            || fname.contains("cms");
        if signish && body.contains("time.Now") {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_241,
                file,
                line,
                col,
                "signing path re-marshals ASN.1 with a fresh time.Now; cache immutable DER and only re-marshal time-varying attributes",
                out,
            );
            return;
        }
        search = start + 8;
    }
}

/// PERF-242: Per-iteration `make([]byte, … len(x)*N …)` on a loop encode path.
pub(crate) fn detect_perf_242(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let file = unit.display_path.as_str();

    for &(loop_start, loop_end) in &facts.for_ranges {
        let end = loop_end.min(source.len()).max(loop_start);
        let loop_text = &source[loop_start..end];
        if !loop_text.contains("make([]byte") {
            continue;
        }
        // Capacity or length derived from len(x)*const — classic encode scratch.
        if !(loop_text.contains("len(") && loop_text.contains('*')) {
            continue;
        }
        let Some(rel) = loop_text.find("make([]byte") else {
            continue;
        };
        let abs = loop_start + rel;
        let (line, col) = unit.line_col(abs);
        emit::push_finding(
            &META_PERF_242,
            file,
            line,
            col,
            "loop allocates make([]byte, … len(x)*N …) each iteration; reuse a scratch buffer with [:0] growth",
            out,
        );
        return;
    }
}

fn map_name_before_make(head: &str) -> Option<String> {
    // … name := make(map[int
    let trimmed = head.trim_end();
    let assign = trimmed.rfind(":=").or_else(|| trimmed.rfind('='))?;
    let before = trimmed[..assign].trim_end();
    // take last identifier
    let name = before
        .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|s| !s.is_empty())?;
    if name.is_empty() || !is_simple_ident(name) {
        return None;
    }
    // Skip short names that are often loops: i, j — still allow m, offsets, etc.
    Some(name.to_string())
}

fn char_boundary_local(s: &str, mut index: usize) -> usize {
    let len = s.len();
    if index > len {
        index = len;
    }
    while !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

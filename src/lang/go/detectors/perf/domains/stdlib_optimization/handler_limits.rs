//! HTTP handler limits and loop-key stdlib smells (PERF-109–PERF-164).

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{char_boundary, file_has_handler};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_109(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for ") {
        return;
    }

    for (start, end) in &facts.for_ranges {
        let end = char_boundary(source, (*end).min(source.len()).max(*start));
        // Prefer the real loop span when available; fall back to a window.
        let range_end = if end > *start {
            end
        } else {
            char_boundary(source, (*start + 1024).min(source.len()))
        };
        let range_text = &source[*start..range_end];
        // Expensive key construction used as a map index inside the loop.
        for marker in &[
            "fmt.Sprintf(",
            "fmt.Sprint(",
            "strings.Join(",
            "strings.ToLower(",
            "strings.ToUpper(",
            "strconv.Itoa(",
            "strconv.FormatInt(",
            "strconv.FormatUint(",
            "filepath.Join(",
        ] {
            if !range_text.contains(marker) {
                continue;
            }
            // Map write/read in the same loop body (`m[key]`, `out[key]++`).
            if !(range_text.contains('[') && range_text.contains(']')) {
                continue;
            }
            // Require an assignment of the expensive result or direct index.
            let uses_as_key = range_text.contains("]++")
                || range_text.contains("] =")
                || range_text.contains("]=")
                || range_text.contains("],")
                || range_text.contains("[key]")
                || range_text.contains("[k]")
                || range_text.lines().any(|l| {
                    let t = l.trim();
                    t.contains(marker.trim_end_matches('(')) && t.contains('[')
                })
                || range_text.contains("key :=")
                || range_text.contains("key=");
            if !uses_as_key && !range_text.contains(marker) {
                continue;
            }
            // Default: expensive marker + map index in loop is enough (existing fixture).
            let (line, col) = unit.line_col(*start);
            emit::push_finding(
                &META_PERF_109,
                file,
                line,
                col,
                "expensive map-key computation inside the loop; cache or simplify the key",
                out,
            );
            return;
        }

        // Same expensive callee text appears ≥2 times in the loop with a map
        // index — true recompute of a key helper.
        if range_text.matches("fmt.Sprintf(").count() >= 2
            && range_text.contains('[')
            && range_text.contains(']')
        {
            let (line, col) = unit.line_col(*start);
            emit::push_finding(
                &META_PERF_109,
                file,
                line,
                col,
                "map key is recomputed multiple times in the loop; cache it per iteration or hoist if invariant",
                out,
            );
            return;
        }
    }
}

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

pub(crate) fn detect_perf_143(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    // Ignore comment/doc text: libraries often document `http.Handle` usage
    // without actually registering a route in this package.
    let Some(pos) = find_code_occurrence(source, "http.HandleFunc")
        .or_else(|| find_code_occurrence(source, "http.Handle("))
    else {
        return;
    };
    if find_code_occurrence(source, "http.TimeoutHandler").is_some() {
        return;
    }
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

/// First byte offset of `needle` outside line/block comments and string literals.
fn find_code_occurrence(source: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let n = needle.as_bytes();
    if bytes.len() < n.len() {
        return None;
    }

    let mut i = 0usize;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut in_string: Option<u8> = None;
    let mut raw_string = false;

    while i + n.len() <= bytes.len() {
        let b = bytes[i];
        if line_comment {
            if b == b'\n' {
                line_comment = false;
            }
            i += 1;
            continue;
        }
        if block_comment {
            if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                block_comment = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(delim) = in_string {
            if raw_string {
                if b == delim {
                    in_string = None;
                    raw_string = false;
                }
                i += 1;
                continue;
            }
            if b == b'\\' {
                i = (i + 2).min(bytes.len());
                continue;
            }
            if b == delim {
                in_string = None;
            }
            i += 1;
            continue;
        }
        if b == b'/' {
            match bytes.get(i + 1) {
                Some(b'/') => {
                    line_comment = true;
                    i += 2;
                    continue;
                }
                Some(b'*') => {
                    block_comment = true;
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        match b {
            b'"' | b'\'' => {
                in_string = Some(b);
                i += 1;
                continue;
            }
            b'`' => {
                in_string = Some(b'`');
                raw_string = true;
                i += 1;
                continue;
            }
            _ => {}
        }
        if bytes[i..].starts_with(n) {
            return Some(i);
        }
        i += 1;
    }
    None
}

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
        let range_text = &source[*start..char_boundary(source, (*start + 512).min(source.len()))];
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
}

pub(crate) fn detect_perf_155(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !file_has_handler(source) && !facts.source_index.has("http.ResponseWriter") {
        return;
    }
    if !source.contains("r.Method") && !source.contains("req.Method") {
        return;
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
}

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
        let pre = &source[char_boundary(source, pre_start)..call.start_byte];
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
}

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
        if callee != "db.Ping"
            && callee != "db.PingContext"
            && !callee.ends_with(".Ping")
            && !callee.ends_with(".PingContext")
        {
            continue;
        }
        // The call must not be in a health-check function. We
        // approximate by looking at the 64 bytes before the
        // call for `func Health` or `func (h *Health`.
        let pre_start = call.start_byte.saturating_sub(256);
        let pre = &source[char_boundary(source, pre_start)..call.start_byte];
        if pre.contains("func Health")
            || pre.contains("func (h *Health")
            || pre.contains("func Healthz")
        {
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
}

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

    let triggers = ["db.Query(", "db.Exec(", "db.Prepare(", "db.Begin("];
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
}

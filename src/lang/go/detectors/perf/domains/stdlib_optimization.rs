//! Migrated from hot_path_misc.rs: domain-specific Stdlib Optimization PERF detectors.
//!
//! PERF-109, PERF-142, PERF-143, PERF-144, PERF-152, PERF-153, PERF-154, PERF-155, PERF-160, PERF-162, PERF-164, PERF-180, PERF-184, PERF-185, PERF-187, PERF-188, PERF-189, PERF-196, PERF-197, PERF-199, PERF-200, PERF-201, PERF-202, PERF-205, PERF-206, PERF-207, PERF-210, PERF-212

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{char_boundary, file_has_handler, is_handler_shaped, is_in_loop};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_109(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for ") {
        return;
    }

    for (start, _end) in &facts.for_ranges {
        let range_text = &source[*start..char_boundary(source, (*start + 1024).min(source.len()))];
        // Look for an expensive key computation inside the
        // loop body. The marker must be followed by use as a
        // map index in the same loop body.
        for marker in &[
            "fmt.Sprintf(",
            "strings.Join(",
            "strings.ToLower(",
            "strings.ToUpper(",
        ] {
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

pub(crate) fn detect_perf_187(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "template.HTMLEscaper" && call.callee.as_ref() != "HTMLEscaper" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
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

pub(crate) fn detect_perf_188(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.calls {
        if call.callee.as_ref() != "fmt.Sscanf" {
            continue;
        }
        if !is_in_loop(call) && !is_handler_shaped(&unit.source, call.start_byte) {
            continue;
        }
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

pub(crate) fn detect_perf_189(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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
}

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
        let pre = &source[char_boundary(source, pre_start)..rel];
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
}

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
                let func_start = source[..pos].rfind("func ").unwrap_or(0);
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
}

pub(crate) fn detect_perf_200(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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
        }
    }
}

pub(crate) fn detect_perf_201(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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
}

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
}

pub(crate) fn detect_perf_205(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
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
}

pub(crate) fn detect_perf_206(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("Unsafe(") {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !callee.ends_with(".Where") && !callee.ends_with(".Find") && !callee.ends_with(".First")
        {
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
}

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
        let window =
            &source[char_boundary(source, call.start_byte.saturating_sub(512))..char_boundary(source, (call.start_byte + 512).min(source.len()))];
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
}

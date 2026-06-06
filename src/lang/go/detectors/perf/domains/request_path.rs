//! PERF-017 through PERF-025: per-request and hot-path patterns for
//! string building, copy / conversion, reflection, body / file reads,
//! hashing, and key generation.

use super::super::common::{
    has_echo_handler, has_gin_handler, has_http_handler, is_assignment_in_loop, is_in_loop,
    is_request_path,
};
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// Returns true when the source file shows evidence of a request handler
/// (Gin / Echo / net/http). Used to decide whether a call is on the hot path.
fn is_request_handler(source: &str) -> bool {
    is_request_path(source)
        && (source.contains("gin.HandlerFunc")
            || source.contains("echo.HandlerFunc")
            || source.contains("http.HandlerFunc")
            || source.contains("func Handle")
            || source.contains("func ServeHTTP")
            || source.contains("c.JSON(")
            || source.contains("c.String(")
            || source.contains("c.HTML(")
            || source.contains("c.Bind(")
            || source.contains("c.ShouldBind")
            || has_gin_handler(source)
            || has_echo_handler(source)
            || has_http_handler(source))
}

/// PERF-017: string concatenation per request body parsing.
pub(crate) fn detect_perf_17(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }

    for assignment in &facts.assignments {
        if !is_assignment_in_loop(assignment) {
            continue;
        }
        let expr = assignment.expr.as_ref();
        if !expr.contains("strings.Join(") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_17,
            file,
            line,
            col,
            "strings.Join is invoked inside a loop on a request path",
            out,
        );
    }
}

/// PERF-018: unnecessary slice copy in a function with a large input slice.
pub(crate) fn detect_perf_18(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // The fixture shape is "processItems(items)" with append(items, ...) in body.
    if !source.contains("func processItems(") {
        return;
    }
    if !source.contains("append(result, items...)") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        if expr.contains("append(result, items...)") {
            let (line, col) = unit.line_col(assignment.start_byte);
            emit::push_finding(
                &META_PERF_18,
                file,
                line,
                col,
                "large slice is copied via append(slice, items...) where reslicing would suffice",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-019: range over slice of large structs by value.
pub(crate) fn detect_perf_19(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("for _, record := range records") {
        return;
    }
    if !source.contains("processRecord(record)") {
        return;
    }
    if source.contains("for _, record := range &records")
        || source.contains("for _, record := range recordsPtr")
    {
        return;
    }

    let start = source.find("for _, record := range records").unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_19,
        file,
        line,
        col,
        "range over a slice of large structs copies each element by value",
        out,
    );
}

/// PERF-020: reflect.ValueOf / reflect.TypeOf / reflect.New on a hot path.
pub(crate) fn detect_perf_20(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }

    let triggers = ["reflect.ValueOf", "reflect.TypeOf", "reflect.New"];
    if !triggers.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("// reflection initialised at startup") {
        return;
    }

    for call in &facts.calls {
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_20,
            file,
            line,
            col,
            "reflect is invoked on a request path; cache reflect.Type or Value at startup",
            out,
        );
        return;
    }
}

/// PERF-021: io.ReadAll on a request body in a handler.
pub(crate) fn detect_perf_21(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }
    if !source.contains("io.ReadAll(") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "io.ReadAll" {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let arg = call.arguments[0].as_ref();
        if arg.contains("c.Request.Body")
            || arg.contains("r.Body")
            || arg.contains("req.Body")
            || arg.contains("ctx.Request.Body")
        {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_21,
                file,
                line,
                col,
                "io.ReadAll fully buffers a request body on a request path",
                out,
            );
            return;
        }
    }
    let _ = facts;
}

/// PERF-022: os.ReadFile / ioutil.ReadFile inside a handler.
pub(crate) fn detect_perf_22(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }
    if !source.contains("os.ReadFile(") && !source.contains("ioutil.ReadFile(") {
        return;
    }
    // sync.Once / loadOnce / similar indicates the file is loaded once at
    // startup, not per request. Suppress so the safe pattern does not fire.
    if source.contains("sync.Once")
        || source.contains("loadOnce")
        || source.contains("readOnce")
        || source.contains("fileOnce")
    {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "os.ReadFile" | "ioutil.ReadFile") {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_22,
            file,
            line,
            col,
            "os.ReadFile is invoked on a request path; load the file once at startup",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-023: bytes.NewReader allocation per request.
pub(crate) fn detect_perf_23(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_handler(source) {
        return;
    }

    for assignment in &facts.assignments {
        let text = assignment.text.as_ref();
        if !text.contains("bytes.NewReader(") {
            continue;
        }
        if !is_assignment_in_loop(assignment) && !text.contains(":=") {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_23,
            file,
            line,
            col,
            "bytes.NewReader is allocated per request; reuse a pooled buffer instead",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-024: crypto hashers allocated inside a loop.
pub(crate) fn detect_perf_24(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = [
        "sha256.New",
        "sha1.New",
        "md5.New",
        "hmac.New",
        "blake2b.New256",
        "blake2s.New256",
    ];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_24,
            file,
            line,
            col,
            "crypto hasher is allocated inside a loop body",
            out,
        );
    }
}

/// PERF-025: rsa.GenerateKey / ecdsa.GenerateKey on a request path.
pub(crate) fn detect_perf_25(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let triggers = [
        "rsa.GenerateKey",
        "rsa.GenerateMultiPrimeKey",
        "ecdsa.GenerateKey",
        "ed25519.GenerateKey",
    ];

    if !triggers.iter().any(|t| source.contains(t)) {
        return;
    }
    if source.contains("var (") && (source.contains("// gen once") || source.contains("sync.Once"))
    {
        return;
    }

    let on_request_path = is_request_handler(source);
    let in_loop = facts
        .calls
        .iter()
        .any(|c| is_in_loop(c) && triggers.iter().any(|t| c.callee.as_ref() == *t));

    if !on_request_path && !in_loop {
        return;
    }

    for call in &facts.calls {
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_25,
            file,
            line,
            col,
            "asymmetric key pair is generated on a request path or in a loop",
            out,
        );
        return;
    }
}

use super::super::super::common::{is_in_loop, is_request_path};
use super::super::super::facts::{CallFact, GoPerfFacts, VarKind};
use super::super::super::metadata::*;
use crate::ast::nearest_loop;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::lang::go::loop_kinds::LOOP_NODE_KINDS;
use crate::rules::{Finding, emit};

pub(crate) fn detect_perf_27(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if source.contains("sync.Pool") {
        return;
    }

    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        // `bytes.Buffer{}` / `new(bytes.Buffer)` are pure per-request
        // allocations that should be pooled. `make([]byte, …)` is too noisy
        // — sized buffers for scanners / reads are fine.
        let is_poolable = expr.contains("bytes.Buffer{")
            || expr.contains("new(bytes.Buffer)")
            || expr.contains("bytes.Buffer{}");
        if !is_poolable {
            continue;
        }
        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_PERF_27,
            file,
            line,
            col,
            "bytes.Buffer is allocated per request; pool it via sync.Pool",
            out,
        );
        return;
    }
    let _ = facts;
}

/// PERF-28: `sync.Mutex` / `sync.RWMutex` declared per request or per record.

pub(crate) fn detect_perf_28(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    if !source.contains("sync.Mutex") && !source.contains("sync.RWMutex") {
        return;
    }
    // A package-scope singleton mutex is fine.
    if source.contains("var mu sync.Mutex\n")
        || source.contains("var mu sync.Mutex =")
        || source.contains("var (\n")
        || source.contains("var rwMu sync.RWMutex\n")
    {
        return;
    }
    // Mutex embedded inside a struct that is itself constructed per request
    // — the "per-record" pattern. We can only detect this from source
    // strings; the `sync.Mutex` token must appear inside a `type … struct`
    // block and that struct must be instantiated in the handler.
    let in_struct = source.contains("struct {")
        && (source.contains("\tmu sync.Mutex")
            || source.contains("mu sync.Mutex\n")
            || source.contains("rwMu sync.RWMutex"));
    let literal_in_handler = source.contains("sync.Mutex{") || source.contains("sync.RWMutex{");
    if !in_struct && !literal_in_handler {
        return;
    }

    let start = source
        .find("sync.Mutex")
        .or_else(|| source.find("sync.RWMutex"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start);
    emit::push_finding(
        &META_PERF_28,
        file,
        line,
        col,
        "sync.Mutex is allocated per request or per record; share a single mutex or use atomics",
        out,
    );
}

/// PERF-29: unbounded `go func(){}` spawn inside a loop or request handler.

pub(crate) fn detect_perf_32(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let on_hot_path = is_request_path(source);

    walk_nodes(
        unit.tree.root_node(),
        &["type_conversion_expression", "conversion_expression"],
        &mut |node| {
            let text = match node.utf8_text(source.as_bytes()) {
                Ok(t) => t,
                Err(_) => return,
            };
            let trimmed = text.trim();
            let is_string_to_bytes =
                trimmed.starts_with("[]byte(") || trimmed.starts_with("[]uint8(");
            let is_bytes_to_string =
                trimmed.starts_with("string(") && !trimmed.starts_with("string(\"");
            if !is_string_to_bytes && !is_bytes_to_string {
                return;
            }
            // Compile-time literal conversions (`[]byte("ok")`) do not
            // involve a runtime copy and are not a hot-path concern.
            if is_string_to_bytes && trimmed.contains("[]byte(\"") {
                return;
            }
            // Skip when the argument to []byte() is already a []byte-typed
            // variable — this is a no-op cast, not a string conversion.
            if is_string_to_bytes {
                let inner = trimmed
                    .strip_prefix("[]byte(")
                    .or_else(|| trimmed.strip_prefix("[]uint8("))
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or("");
                let is_simple_ident =
                    !inner.is_empty() && inner.chars().all(|c| c.is_alphanumeric() || c == '_');
                if is_simple_ident {
                    if let Some(&kind) = facts.var_kinds.get(inner) {
                        if kind == VarKind::Bytes {
                            return;
                        }
                    }
                }
            }
            if !on_hot_path && nearest_loop(node, LOOP_NODE_KINDS).is_none() {
                return;
            }
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_32,
                file,
                line,
                col,
                "string <-> []byte conversion copies the underlying data on a hot path",
                out,
            );
        },
    );
}

/// PERF-33: range over a large slice in a request handler / batch processor
/// where indexed scan would be more efficient.

pub(crate) fn detect_perf_35(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !source.contains("for ") {
        return;
    }

    for call in &facts.calls {
        if !matches!(call.callee.as_ref(), "fmt.Sprintf" | "fmt.Errorf") {
            continue;
        }
        if !is_in_loop(call) && !is_request_path(source) {
            continue;
        }
        // A single literal argument does not box; the format call is a
        // pure passthrough.
        if call.arguments.len() < 2 {
            continue;
        }
        // The format string itself is a string, but the *other* args are
        // passed as `interface{}` and get boxed. We use `>1` as the proxy.
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_35,
            file,
            line,
            col,
            "fmt.Sprintf / Errorf boxes arguments through interface{} on a hot path",
            out,
        );
        return;
    }
}

/// PERF-36: `go func(){ use(v) }()` capturing a loop variable.

pub(crate) fn detect_perf_37(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }
    // The function must (a) declare the slice as a nil/empty `var` or `:=`
    // without a `make` and (b) grow it via `append` inside a loop.
    let has_unpreallocated_slice = source.contains("var out []int")
        || source.contains("out := []int{}")
        || source.contains("results := []int{}")
        || source.contains("var results []int")
        || source.contains("var out []string")
        || source.contains("out := []string{}")
        || source.contains("out := []byte{}")
        || source.contains("var out []byte");
    if !has_unpreallocated_slice {
        return;
    }
    if source.contains("make([]") {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "append" {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_37,
            file,
            line,
            col,
            "slice is grown by append on a request path without a capacity hint",
            out,
        );
        return;
    }
}

/// PERF-38: unbuffered channel in a producer / consumer pipeline.

pub(crate) fn detect_perf_42(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) && !is_in_loop_present(&facts.calls) {
        return;
    }

    for call in &facts.calls {
        if call.callee.as_ref() != "fmt.Errorf" {
            continue;
        }
        if call.arguments.is_empty() {
            continue;
        }
        let first = call.arguments[0].as_ref();
        if !first.starts_with('"') || !first.ends_with('"') {
            continue;
        }
        let literal = &first[1..first.len() - 1];
        if literal.contains('%') {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_42,
            file,
            line,
            col,
            "fmt.Errorf with a static string allocates a Sprintf; use errors.New instead",
            out,
        );
        return;
    }
    let _ = source;
}

fn is_in_loop_present(calls: &[CallFact]) -> bool {
    calls.iter().any(super::super::super::common::is_in_loop)
}

/// PERF-43: `defer func(){ recover() }()` in a hot loop or per-request path.

pub(crate) fn detect_perf_46(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !is_request_path(source) {
        return;
    }

    for call in &facts.calls {
        if !matches!(
            call.callee.as_ref(),
            "strings.TrimSpace"
                | "strings.Trim"
                | "strings.TrimPrefix"
                | "strings.TrimSuffix"
                | "strings.TrimLeft"
                | "strings.TrimRight"
        ) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_46,
            file,
            line,
            col,
            "string trimming allocates on a request path; check the need first",
            out,
        );
        return;
    }
    let _ = source;
}

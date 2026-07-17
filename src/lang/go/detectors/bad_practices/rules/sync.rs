//! BP-6, BP-7, BP-8, BP-9, BP-12, BP-14 — concurrency/synchronisation bad practices.

use super::super::source_index::SourceIndex;
use super::helpers::{line_start_byte, push_at};
use crate::core::ParsedUnit;
use crate::rules::Finding;
use tree_sitter::Node;

/// BP-6: sync.WaitGroup.Add inside the goroutine it tracks.
///
/// Uses the AST-scoped `func_literal` body and attributes nested goroutines
/// only to their own `go_statement`.
pub(crate) fn detect_bp_6_waitgroup_add_inside_goroutine(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("go func") || !index.has(".Add(") {
        return;
    }
    crate::ast::walk_nodes(
        unit.tree.root_node(),
        &["go_statement"],
        &mut |go_statement| {
            let Some(body) = function_literal_body(go_statement) else {
                return;
            };
            push_waitgroup_adds_in_goroutine(unit, body, out);
        },
    );
}

/// BP-7: sync.Mutex copied by function parameter value.
pub(crate) fn detect_bp_7_mutex_passed_by_value(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("sync.Mutex") && !unit.source.contains("sync.Mutex") {
        return;
    }
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
    if !(index.has("defer ") && index.has(".Unlock()")) {
        return;
    }
    crate::ast::walk_nodes(
        unit.tree.root_node(),
        &["function_declaration", "method_declaration"],
        &mut |function| {
            let mutex_params = by_value_mutex_parameter_names(function, unit.source.as_bytes());
            if mutex_params.is_empty() {
                return;
            }
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            crate::ast::walk_nodes(body, &["defer_statement"], &mut |defer_statement| {
                let Ok(text) = defer_statement.utf8_text(unit.source.as_bytes()) else {
                    return;
                };
                let Some(receiver) = text
                    .trim_start()
                    .strip_prefix("defer ")
                    .and_then(|call| call.trim().strip_suffix(".Unlock()"))
                    .map(str::trim)
                else {
                    return;
                };
                if mutex_params.contains(&receiver) {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_8_META,
                        defer_statement.start_byte(),
                        "defer unlock is operating on a mutex value copy; pass *sync.Mutex",
                    );
                }
            });
        },
    );
}

/// BP-9: select without default, timeout, or context cancellation.
///
/// Uses AST select statements and ignores control-flow lookalikes in prose.
pub(crate) fn detect_bp_9_select_without_escape(
    unit: &ParsedUnit,
    index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !index.has("select") {
        return;
    }
    crate::ast::walk_nodes(
        unit.tree.root_node(),
        &["select_statement"],
        &mut |select_statement| {
            let Ok(block) = select_statement.utf8_text(unit.source.as_bytes()) else {
                return;
            };
            let has_escape = contains_code_token(block, "default:")
                || contains_code_token(block, "time.After(")
                || contains_code_token(block, "time.NewTimer(")
                || contains_code_token(block, "ctx.Done()")
                || contains_code_token(block, "context.Done()")
                || contains_code_token(block, "<-stop")
                || contains_code_token(block, "<-done")
                || contains_code_token(block, "<-ctx.Done()");
            if !has_escape {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_9_META,
                    select_statement.start_byte(),
                    "select can block indefinitely without default, timeout, or context cancellation",
                );
            }
        },
    );
}

fn function_literal_body(node: Node) -> Option<Node> {
    if node.kind() == "func_literal" {
        return node.child_by_field_name("body");
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(function_literal_body)
}

fn push_waitgroup_adds_in_goroutine(unit: &ParsedUnit, body: Node, out: &mut Vec<Finding>) {
    fn visit(unit: &ParsedUnit, node: Node, out: &mut Vec<Finding>) {
        if node.kind() == "go_statement" {
            return;
        }
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && let Ok(name) = function.utf8_text(unit.source.as_bytes())
            && name.ends_with(".Add")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_6_META,
                node.start_byte(),
                "WaitGroup.Add is inside the goroutine; call Add before launching it",
            );
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(unit, child, out);
        }
    }

    visit(unit, body, out);
}

fn by_value_mutex_parameter_names<'a>(function: Node, source: &'a [u8]) -> Vec<&'a str> {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let Some(ty) = parameter.child_by_field_name("type") else {
            continue;
        };
        if ty.utf8_text(source).ok() != Some("sync.Mutex") {
            continue;
        }
        let mut parameter_cursor = parameter.walk();
        for child in parameter.named_children(&mut parameter_cursor) {
            if child.kind() == "identifier"
                && let Ok(name) = child.utf8_text(source)
            {
                names.push(name);
            }
        }
    }
    names
}

fn skip_quoted_literal(bytes: &[u8], mut i: usize) -> usize {
    let quote = bytes[i];
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

fn contains_code_token(source: &str, needle: &str) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(next) = skip_non_code(bytes, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            _ if bytes[i..].starts_with(needle.as_bytes()) => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Skip a Go literal or comment so text-only fallbacks inspect syntax, not prose.
fn skip_non_code(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes[i] {
        b'\'' | b'"' => Some(skip_quoted_literal(bytes, i)),
        b'`' => bytes[i + 1..]
            .iter()
            .position(|byte| *byte == b'`')
            .map_or(Some(bytes.len()), |offset| Some(i + offset + 2)),
        b'/' if bytes.get(i + 1) == Some(&b'/') => bytes[i + 2..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(Some(bytes.len()), |offset| Some(i + offset + 2)),
        b'/' if bytes.get(i + 1) == Some(&b'*') => bytes[i + 2..]
            .windows(2)
            .position(|window| window == b"*/")
            .map_or(Some(bytes.len()), |offset| Some(i + offset + 4)),
        _ => None,
    }
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

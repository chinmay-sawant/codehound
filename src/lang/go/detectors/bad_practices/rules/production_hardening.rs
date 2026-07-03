//! BP-46..BP-55 — production-hardening bad practices.

use std::fs;
use std::path::PathBuf;

use tree_sitter::Node;
use walkdir::WalkDir;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::engine::discover_project_root;
use crate::rules::Finding;

pub(crate) fn detect_bp_46_http_server_missing_timeouts(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) || !unit.source.contains("http.Server") {
        return;
    }
    for (byte, literal) in http_server_literals(unit.source.as_ref()) {
        if !literal.contains("ReadTimeout:") || !literal.contains("WriteTimeout:") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_46_META,
                byte,
                "http.Server should set both ReadTimeout and WriteTimeout",
            );
        }
    }
}

pub(crate) fn detect_bp_47_no_graceful_shutdown(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let project = read_project_texts(unit);
    if !project.iter().any(|(_, text)| contains_server_start(text)) {
        return;
    }
    if project.iter().any(|(_, text)| text.contains(".Shutdown(")) {
        return;
    }
    push_at(
        unit,
        out,
        &crate::lang::go::detectors::bad_practices::BP_47_META,
        0,
        "server startup should include a graceful shutdown path",
    );
}

pub(crate) fn detect_bp_48_process_exit_in_library_code(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_call_expressions(unit, |call, src| {
        let callee = function_text(call, src)?;
        if !matches!(
            callee,
            "log.Fatal" | "log.Fatalf" | "log.Fatalln" | "os.Exit"
        ) {
            return None;
        }
        (!inside_main_or_testmain(call, src)).then_some((
            call.start_byte(),
            "library code should return errors instead of exiting the process",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_48_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_49_deferred_cleanup_without_error_handling(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_defer_statements(unit, |defer_node, src| {
        let text = node_text(defer_node, src)?;
        if text.contains("func()") {
            return None;
        }
        (text.contains(".Close()")
            || text.contains(".Flush()")
            || text.contains(".Sync()"))
        .then_some((
            defer_node.start_byte(),
            "deferred cleanup drops an error; wrap it in a deferred function and check the result",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_49_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_50_no_signal_handling_for_server(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let project = read_project_texts(unit);
    if !project.iter().any(|(_, text)| contains_server_start(text)) {
        return;
    }
    let has_signal_handling = project.iter().any(|(_, text)| {
        text.contains("signal.Notify(")
            || text.contains("signal.NotifyContext(")
            || text.contains("\"os/signal\"")
    });
    if !has_signal_handling {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_50_META,
            0,
            "long-running server should handle SIGTERM or SIGINT",
        );
    }
}

pub(crate) fn detect_bp_51_recover_without_repanic_in_library(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) || package_name(unit) == Some("main") {
        return;
    }
    walk_call_expressions(unit, |call, src| {
        if function_text(call, src) != Some("recover") {
            return None;
        }
        let scope = enclosing_func_literal_or_function(call)?;
        let scope_text = node_text(scope, src)?;
        let handled = scope_text.contains("panic(")
            || scope_text.contains("log.")
            || scope_text.contains("logger.")
            || scope_text.contains("fmt.");
        (!handled).then_some((
            call.start_byte(),
            "library recover paths should re-panic or convert the panic into an explicit error contract",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_51_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_52_unchecked_integer_multiplication(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) || !unit.source.contains("make(") || !unit.source.contains('*') {
        return;
    }
    walk_call_expressions(unit, |call, src| {
        if function_text(call, src) != Some("make") {
            return None;
        }
        let call_text = node_text(call, src)?;
        if !call_text.contains('*') {
            return None;
        }
        let scope = enclosing_func_literal_or_function(call)?;
        let scope_text = node_text(scope, src)?;
        let has_guard = scope_text.contains("MaxInt")
            || scope_text.contains("MaxUint")
            || scope_text.contains("overflow")
            || scope_text.contains("/")
            || scope_text.contains("bits.Mul")
            || scope_text.contains("checkedMul")
            || scope_text.contains("checked_mul");
        (!has_guard).then_some((
            call.start_byte(),
            "multiplication used in an allocation path without an obvious overflow guard",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_52_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_53_gob_registration_mismatch(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if is_test_file(unit) || !source.contains("gob.Register(") {
        return;
    }
    let registered = collect_call_targets(source, "gob.Register(");
    if registered.is_empty() {
        return;
    }
    let encoded = collect_call_targets(source, ".Encode(");
    let decoded = collect_call_targets(source, ".Decode(");
    let known_types = collect_local_type_hints(source);
    let mut matched = false;
    for value in encoded.iter().chain(decoded.iter()) {
        let normalized = normalize_identifier(value);
        if let Some(ty) = known_types.get(&normalized)
            && registered
                .iter()
                .any(|candidate| normalize_type_name(candidate) == *ty)
        {
            matched = true;
            break;
        }
    }
    if !matched {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_53_META,
            source.find("gob.Register(").unwrap_or(0),
            "gob.Register uses a type that does not line up with the nearby Encode/Decode payloads",
        );
    }
}

pub(crate) fn detect_bp_54_public_http_endpoint_without_rate_limiting(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let project = read_project_texts(unit);
    if !project.iter().any(|(_, text)| contains_server_start(text))
        || !project.iter().any(|(_, text)| contains_public_route(text))
    {
        return;
    }
    let has_rate_limiting = project.iter().any(|(_, text)| {
        text.contains("rate.NewLimiter(")
            || text.contains("rate.Limiter")
            || text.contains("tollbooth")
            || text.contains("httprate")
            || text.contains("Throttle(")
    });
    if !has_rate_limiting {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_54_META,
            0,
            "public HTTP handlers should enforce a rate-limiting guard",
        );
    }
}

pub(crate) fn detect_bp_55_missing_request_id_propagation(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let project = read_project_texts(unit);
    if !project.iter().any(|(_, text)| contains_server_start(text))
        || !project.iter().any(|(_, text)| contains_public_route(text))
        || !project.iter().any(|(_, text)| {
            text.contains("log.") || text.contains("logger.") || text.contains("slog.")
        })
    {
        return;
    }
    let has_request_id = project.iter().any(|(_, text)| {
        text.contains("Request-ID")
            || text.contains("Request-Id")
            || text.contains("X-Request-ID")
            || text.contains("X-Request-Id")
            || text.contains("requestid")
            || text.contains("request_id")
            || text.contains("RequestID")
    });
    if !has_request_id {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_55_META,
            0,
            "request-handling code logs traffic without a visible request-id propagation path",
        );
    }
}

fn is_test_file(unit: &ParsedUnit) -> bool {
    unit.display_path.ends_with("_test.go")
}

fn is_materialized_fixture(unit: &ParsedUnit) -> bool {
    let display = unit.display_path.as_str();
    display.contains("target/slopguard-fixtures/")
        || display.contains("target\\slopguard-fixtures\\")
}

fn http_server_literals(source: &str) -> Vec<(usize, &str)> {
    let mut literals = Vec::new();
    let bytes = source.as_bytes();
    let mut start = 0;
    while let Some(offset) = source[start..].find("http.Server{") {
        let idx = start + offset;
        let mut depth = 0usize;
        let mut end = idx;
        for (cursor, byte) in bytes[idx..].iter().enumerate() {
            if *byte == b'{' {
                depth += 1;
            } else if *byte == b'}' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = idx + cursor + 1;
                    break;
                }
            }
        }
        if end > idx {
            literals.push((idx, &source[idx..end]));
        }
        start = idx + "http.Server{".len();
    }
    literals
}

fn walk_call_expressions(
    unit: &ParsedUnit,
    mut visit: impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
) -> Vec<(usize, &'static str)> {
    let mut findings = Vec::new();
    fn walk(
        node: Node,
        src: &[u8],
        findings: &mut Vec<(usize, &'static str)>,
        visit: &mut impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
    ) {
        if node.kind() == "call_expression"
            && let Some(finding) = visit(node, src)
        {
            findings.push(finding);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, findings, visit);
        }
    }
    walk(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        &mut findings,
        &mut visit,
    );
    findings
}

fn walk_defer_statements(
    unit: &ParsedUnit,
    mut visit: impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
) -> Vec<(usize, &'static str)> {
    let mut findings = Vec::new();
    fn walk(
        node: Node,
        src: &[u8],
        findings: &mut Vec<(usize, &'static str)>,
        visit: &mut impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
    ) {
        if node.kind() == "defer_statement"
            && let Some(finding) = visit(node, src)
        {
            findings.push(finding);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, findings, visit);
        }
    }
    walk(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        &mut findings,
        &mut visit,
    );
    findings
}

fn function_text<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(src).ok()
}

fn node_text<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(src).ok()
}

fn inside_main_or_testmain(node: Node, src: &[u8]) -> bool {
    let mut current = Some(node);
    while let Some(cursor) = current {
        if matches!(cursor.kind(), "function_declaration" | "method_declaration")
            && let Some(name) = cursor
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
        {
            return matches!(name, "main" | "TestMain");
        }
        current = cursor.parent();
    }
    false
}

fn enclosing_func_literal_or_function(node: Node) -> Option<Node> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "func_literal" | "function_declaration" | "method_declaration"
        ) {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn package_name(unit: &ParsedUnit) -> Option<&str> {
    for line in unit.source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            return Some(rest.trim());
        }
    }
    None
}

fn read_project_texts(unit: &ParsedUnit) -> Vec<(PathBuf, String)> {
    let root = discover_project_root(&unit.path);
    let mut files = Vec::new();
    for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(path) {
            files.push((path.to_path_buf(), text));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn contains_server_start(text: &str) -> bool {
    text.contains("ListenAndServe(")
        || text.contains(".ListenAndServe(")
        || text.contains(".Serve(")
        || text.contains("http.Serve(")
}

fn contains_public_route(text: &str) -> bool {
    text.contains("HandleFunc(")
        || text.contains(".HandleFunc(")
        || text.contains(".Handle(")
        || text.contains(".GET(")
        || text.contains(".POST(")
        || text.contains(".PUT(")
        || text.contains(".DELETE(")
        || text.contains(".PATCH(")
}

fn collect_call_targets(source: &str, needle: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut start = 0usize;
    while let Some(offset) = source[start..].find(needle) {
        let idx = start + offset + needle.len();
        if let Some(end) = source[idx..].find(')') {
            values.push(source[idx..idx + end].trim().to_string());
            start = idx + end + 1;
        } else {
            break;
        }
    }
    values
}

fn collect_local_type_hints(source: &str) -> std::collections::BTreeMap<String, String> {
    let mut types = std::collections::BTreeMap::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some((name, value)) = trimmed.split_once(":=") {
            let rhs = value.trim();
            if let Some((ty, _)) = rhs.split_once('{') {
                let ident = ty.trim().trim_start_matches('&').trim_start_matches('*');
                if !ident.is_empty() {
                    types.insert(name.trim().to_string(), ident.to_string());
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("var ") {
            let mut parts = rest.split_whitespace();
            let name = parts.next().unwrap_or("");
            let ty = parts.next().unwrap_or("");
            if !name.is_empty() && !ty.is_empty() {
                types.insert(name.to_string(), ty.trim_start_matches('*').to_string());
            }
        }
    }
    types
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_matches(|c: char| c == ')' || c == '(')
        .to_string()
}

fn normalize_type_name(value: &str) -> String {
    let value = value.trim();
    if let Some((ty, _)) = value.split_once('{') {
        return normalize_identifier(ty);
    }
    if value.contains("nil") {
        return value
            .trim_matches(|c: char| c == '(' || c == ')' || c == '*')
            .split_whitespace()
            .next()
            .unwrap_or(value)
            .to_string();
    }
    normalize_identifier(value)
}

fn is_project_anchor(unit: &ParsedUnit) -> bool {
    let root = discover_project_root(&unit.path);
    let mut files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("go"))
        .filter(|path| !path.to_string_lossy().ends_with("_test.go"))
        .collect();
    files.sort();
    files.first().is_some_and(|path| path == &unit.path)
}

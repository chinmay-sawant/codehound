// Batch D — overlap-gated resource, error, RPC, and CLI checks.
//
// These rules deliberately use only facts visible in one Go file. They are
// not replacements for bodyclose, errcheck, gRPC policy, or Cobra review;
// registration and metadata remain coordinator-owned.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-95: a locally acquired HTTP response has no visible close or ownership
/// transfer. Only direct `http.Get`/`http.Post`/`http.Head` and `*.Do` calls
/// are considered; aliases and helper-owned responses remain out of scope.
pub(crate) fn detect_bp_95_http_response_body_not_closed(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "net/http") {
        return;
    }

    walk_functions(root, source, &mut |function| {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut candidates = Vec::new();
        walk_scope(body, body, &mut |node| {
            if let Some((response, byte)) = response_binding(node, source) {
                candidates.push((response, byte));
            }
        });

        for (response, byte) in candidates {
            if !has_response_release(body, source, &response) {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_95_META,
                    byte,
                    "HTTP response body has no visible Close or ownership transfer; close resp.Body after a successful client request",
                );
            }
        }
    });
}

/// BP-154: a direct `json.Unmarshal` call is used as an expression statement,
/// discarding its error. Blank assignments are intentionally excluded because
/// BP-1 already reports that exact ignored-error form.
pub(crate) fn detect_bp_154_json_unmarshal_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "encoding/json") {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "call_expression"
            || call_name(node, source) != Some("json.Unmarshal")
            || node
                .parent()
                .is_none_or(|parent| parent.kind() != "expression_statement")
        {
            return;
        }
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_154_META,
            node.start_byte(),
            "json.Unmarshal error is discarded; check and handle the returned error",
        );
    });
}

/// BP-158: a gRPC-shaped service method returns a raw local error instead of
/// a status error, or discards `status.FromError` as a bare expression. The
/// method and import gates avoid treating ordinary context-aware functions as
/// gRPC handlers.
pub(crate) fn detect_bp_158_grpc_error_handling(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_grpc_import(root, source) {
        return;
    }

    walk_functions(root, source, &mut |function| {
        if function.kind() != "method_declaration" || !is_grpc_handler(function, source) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        walk_scope(body, body, &mut |node| {
            if node.kind() == "call_expression"
                && call_name(node, source) == Some("status.FromError")
                && node
                    .parent()
                    .is_none_or(|parent| parent.kind() == "expression_statement")
            {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_158_META,
                    node.start_byte(),
                    "status.FromError result is discarded; preserve the gRPC status or handle the error explicitly",
                );
            }

            if node.kind() != "return_statement" || !returns_raw_error(node, source) {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_158_META,
                node.start_byte(),
                "gRPC handler returns a naked error; return a status.Error or status.Errorf with an appropriate code",
            );
        });
    });
}

/// BP-160: a Cobra command literal supplies `Run` but no `RunE`. This is an
/// advisory boundary: command authors may intentionally handle all errors in
/// Run, so this detector does not claim that every Run callback is incorrect.
pub(crate) fn detect_bp_160_cobra_run_without_run_e(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "github.com/spf13/cobra") {
        return;
    }

    walk_nodes(root, &mut |node| {
        if node.kind() != "composite_literal" || !is_cobra_command(node, source) {
            return;
        }
        let (has_run, has_run_e) = cobra_run_fields(node, source);
        if has_run && !has_run_e {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_160_META,
                node.start_byte(),
                "Cobra command uses Run without RunE; return command errors through RunE so Execute can report them",
            );
        }
    });
}

fn response_binding(node: Node, source: &[u8]) -> Option<(String, usize)> {
    if !matches!(
        node.kind(),
        "short_var_declaration" | "assignment_statement"
    ) {
        return None;
    }
    let text = node.utf8_text(source).ok()?;
    let (left, right) = text.split_once(":=").or_else(|| text.split_once('='))?;
    let call = right.trim().split('(').next()?.trim();
    if !is_http_request_call(call) {
        return None;
    }
    let response = left
        .split(',')
        .map(str::trim)
        .find(|name| is_identifier(name) && !name.trim().eq("_"))?;
    Some((response.to_owned(), node.start_byte()))
}

fn is_http_request_call(call: &str) -> bool {
    matches!(
        call,
        "http.Get" | "http.Post" | "http.PostForm" | "http.Head" | "http.DefaultClient.Do"
    ) || call.strip_suffix(".Do").is_some_and(is_identifier)
}

fn has_response_release(body: Node, source: &[u8], response: &str) -> bool {
    let close = format!("{response}.Body.Close");
    let mut released = false;
    walk_scope(body, body, &mut |node| {
        if released {
            return;
        }
        if node.kind() == "call_expression"
            && call_name(node, source).is_some_and(|name| name.trim() == close)
        {
            released = true;
            return;
        }
        if node.kind() == "return_statement"
            && node
                .utf8_text(source)
                .is_ok_and(|text| return_mentions_identifier(text, response))
        {
            released = true;
        }
    });
    released
}

fn return_mentions_identifier(text: &str, identifier: &str) -> bool {
    let expression = text.trim().strip_prefix("return").unwrap_or_default();
    expression
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|part| part == identifier)
}

fn is_grpc_handler(function: Node, source: &[u8]) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let Some(result) = function.child_by_field_name("result") else {
        return false;
    };
    let parameters = parameters.utf8_text(source).unwrap_or_default();
    let result = result.utf8_text(source).unwrap_or_default();
    function.child_by_field_name("receiver").is_some()
        && parameters.contains("context.Context")
        && parameters.contains(',')
        && parameters.contains('*')
        && result.contains('*')
        && result.contains("error")
}

fn returns_raw_error(node: Node, source: &[u8]) -> bool {
    let Some(text) = node.utf8_text(source).ok().map(str::trim) else {
        return false;
    };
    let Some(expression) = text.strip_prefix("return").map(str::trim) else {
        return false;
    };
    let values: Vec<_> = expression.split(',').map(str::trim).collect();
    values.len() >= 2 && matches!(values.last().copied(), Some("err" | "error"))
}

fn is_cobra_command(node: Node, source: &[u8]) -> bool {
    node.utf8_text(source).is_ok_and(|text| {
        let text = text.trim_start();
        text.starts_with("cobra.Command") || text.starts_with("&cobra.Command")
    })
}

fn cobra_run_fields(node: Node, source: &[u8]) -> (bool, bool) {
    let mut fields = (false, false);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_cobra_fields(child, source, &mut fields);
    }
    fields
}

fn collect_cobra_fields(node: Node, source: &[u8], fields: &mut (bool, bool)) {
    if node.kind() == "keyed_element" {
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let key = text
            .split_once(':')
            .map_or(text.trim(), |(key, _)| key.trim());
        match key {
            "Run" => fields.0 = true,
            "RunE" => fields.1 = true,
            _ => {}
        }
        return;
    }
    if node.kind() == "composite_literal" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_cobra_fields(child, source, fields);
    }
}

fn call_name<'a>(node: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(source).ok()
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    let needle = format!("\"{path}\"");
    let mut found = false;
    walk_nodes(root, &mut |node| {
        if !found
            && matches!(node.kind(), "import_spec" | "import_declaration")
            && node
                .utf8_text(source)
                .is_ok_and(|text| text.contains(&needle))
        {
            found = true;
        }
    });
    found
}

fn has_grpc_import(root: Node, source: &[u8]) -> bool {
    let mut found = false;
    walk_nodes(root, &mut |node| {
        if !found
            && node.kind() == "import_spec"
            && node
                .utf8_text(source)
                .is_ok_and(|text| text.contains("\"google.golang.org/grpc"))
        {
            found = true;
        }
    });
    found
}

fn walk_functions(root: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if is_function_like(root.kind()) {
        visit(root);
        return;
    }
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_functions(child, source, visit);
    }
    let _ = source;
}

fn walk_scope(root: Node, scope: Node, visit: &mut impl FnMut(Node)) {
    if root.id() != scope.id() && is_function_like(root.kind()) {
        return;
    }
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_scope(child, scope, visit);
    }
}

fn walk_nodes(root: Node, visit: &mut impl FnMut(Node)) {
    visit(root);
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        walk_nodes(child, visit);
    }
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

//! High-signal HTTP/framework candidates that are safe to prove locally.
//!
//! The coordinator owns registration, metadata, dispatch, and fixture-manifest
//! integration. These detectors therefore keep their evidence local and require
//! explicit framework imports wherever a method name could otherwise collide.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-104: the same literal pattern is registered more than once on a
/// `http.ServeMux`. Go 1.22 rejects duplicate patterns at registration time;
/// requiring a concrete `http.NewServeMux` receiver avoids matching arbitrary
/// objects that happen to expose a `Handle` method.
pub(crate) fn detect_bp_104_http_mux_pattern_overlap(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "net/http") {
        return;
    }
    walk_functions(root, source, unit, out, |function, source, unit, out| {
        let muxes = serve_mux_names(function, source);
        if muxes.is_empty() {
            return;
        }

        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut registrations: Vec<(String, usize)> = Vec::new();
        collect_mux_registrations(body, source, &muxes, &mut registrations);

        for (pattern, byte) in &registrations {
            if registrations_before(&registrations, pattern, *byte) {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_104_META,
                    *byte,
                    "ServeMux registers the same literal pattern more than once; the registration will conflict at runtime",
                );
                break;
            }
        }
    });
}

/// BP-105: a sensitive cookie is issued without both transport and script
/// protections. The sensitive-name gate keeps deliberately public cookies
/// (such as a CSRF cookie) out of this correctness rule.
pub(crate) fn detect_bp_105_http_cookie_security_flags_missing(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "net/http") {
        return;
    }
    walk_functions(root, source, unit, out, |function, source, unit, out| {
        if !has_http_handler_shape(function, source) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        collect_cookie_literals(body, source, unit, out);
    });
}

/// BP-107: a typed net/http middleware returns a HandlerFunc that neither
/// delegates to its next handler nor sends an explicit terminal response.
pub(crate) fn detect_bp_107_http_middleware_missing_next(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, "net/http") {
        return;
    }
    detect_missing_next_middleware(
        unit,
        out,
        has_http_middleware_shape,
        &crate::lang::go::detectors::bad_practices::BP_107_META,
        "HTTP middleware returns a handler that neither calls next.ServeHTTP nor writes a terminal response",
    );
}

/// BP-122: the same local middleware proof, constrained by an explicit Chi
/// import so generic net/http middleware is not reported as Chi-specific.
pub(crate) fn detect_bp_122_chi_middleware_missing_next(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import_prefix(root, source, "github.com/go-chi/chi") {
        return;
    }
    detect_missing_next_middleware(
        unit,
        out,
        has_http_middleware_shape,
        &crate::lang::go::detectors::bad_practices::BP_122_META,
        "Chi middleware returns a handler that neither calls next.ServeHTTP nor writes a terminal response",
    );
}

fn detect_missing_next_middleware(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    is_middleware: impl Fn(Node, &[u8]) -> bool + Copy,
    metadata: &crate::rules::RuleMetadata,
    message: &str,
) {
    let source = unit.source.as_bytes();
    walk_functions(
        unit.tree.root_node(),
        source,
        unit,
        out,
        |function, source, unit, out| {
            if !is_middleware(function, source) {
                return;
            }
            let Some(next_names) = typed_parameter_names(function, source, "http.Handler") else {
                return;
            };
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };

            let mut handlers = Vec::new();
            collect_handler_func_calls(body, source, &mut handlers);
            for handler in handlers {
                let Ok(text) = handler.utf8_text(source) else {
                    continue;
                };
                if next_names
                    .iter()
                    .any(|name| has_serve_http_call(text, name))
                    || has_terminal_response(text)
                {
                    continue;
                }
                push_at(unit, out, metadata, handler.start_byte(), message);
            }
        },
    );
}

fn walk_functions(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    inspect: impl Fn(Node, &[u8], &ParsedUnit, &mut Vec<Finding>) + Copy,
) {
    if is_function_like(node.kind()) {
        inspect(node, source, unit, out);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out, inspect);
    }
}

fn serve_mux_names(function: Node, source: &[u8]) -> Vec<String> {
    let Some(body) = function.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    collect_serve_mux_names(body, source, &mut names);
    names
}

fn collect_serve_mux_names(node: Node, source: &[u8], names: &mut Vec<String>) {
    if node.kind() == "call_expression"
        && call_text(node, source).is_some_and(|text| text.contains("http.NewServeMux()"))
        && let Some(parent) = enclosing_assignment(node)
        && let Ok(text) = parent.utf8_text(source)
        && let Some(left) = text.split_once(":=").or_else(|| text.split_once('='))
        && let Some(name) = left.0.split(',').next().map(str::trim)
        && is_identifier(name)
    {
        names.push(name.to_owned());
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !is_function_like(child.kind()) {
            collect_serve_mux_names(child, source, names);
        }
    }
}

fn enclosing_assignment(mut node: Node) -> Option<Node> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "short_var_declaration" | "assignment_statement"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn collect_mux_registrations(
    node: Node,
    source: &[u8],
    muxes: &[String],
    registrations: &mut Vec<(String, usize)>,
) {
    if node.kind() == "call_expression"
        && let Some((receiver, method)) = receiver_method(node, source)
        && muxes.iter().any(|mux| mux == receiver)
        && matches!(method, "Handle" | "HandleFunc")
        && let Some(pattern) = first_string_argument(node, source)
    {
        registrations.push((pattern, node.start_byte()));
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !is_function_like(child.kind()) {
            collect_mux_registrations(child, source, muxes, registrations);
        }
    }
}

fn registrations_before(registrations: &[(String, usize)], pattern: &str, byte: usize) -> bool {
    registrations
        .iter()
        .any(|(previous, previous_byte)| previous == pattern && *previous_byte < byte)
}

fn collect_cookie_literals(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "call_expression"
        && call_text(node, source).is_some_and(|text| text.starts_with("http.SetCookie("))
        && let Some(cookie) = cookie_argument(node)
        && let Ok(text) = cookie.utf8_text(source)
        && sensitive_cookie_name(text)
        && (!cookie_has_true_field(text, "Secure") || !cookie_has_true_field(text, "HttpOnly"))
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_105_META,
            cookie.start_byte(),
            "sensitive HTTP cookie is missing Secure or HttpOnly protection",
        );
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !is_function_like(child.kind()) {
            collect_cookie_literals(child, source, unit, out);
        }
    }
}

fn cookie_argument(call: Node) -> Option<Node> {
    call.child_by_field_name("arguments")?.named_child(1)
}

fn sensitive_cookie_name(text: &str) -> bool {
    let Some(name) = text.split("Name:").nth(1) else {
        return false;
    };
    let name = name
        .trim()
        .split(',')
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .to_ascii_lowercase();
    ["session", "auth", "token", "sid", "jwt", "refresh"]
        .iter()
        .any(|needle| name.contains(needle))
}

fn cookie_has_true_field(text: &str, field: &str) -> bool {
    text.split(field).skip(1).any(|tail| {
        tail.trim_start()
            .strip_prefix(':')
            .is_some_and(|value| value.trim_start().starts_with("true"))
    })
}

fn has_http_handler_shape(function: Node, source: &[u8]) -> bool {
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let text = parameters.utf8_text(source).unwrap_or_default();
    text.contains("http.ResponseWriter") && text.contains("*http.Request")
}

fn has_http_middleware_shape(function: Node, source: &[u8]) -> bool {
    let Some(result) = function.child_by_field_name("result") else {
        return false;
    };
    result
        .utf8_text(source)
        .is_ok_and(|text| text.contains("http.Handler"))
        && !typed_parameter_names(function, source, "http.Handler")
            .is_none_or(|names| names.is_empty())
}

fn typed_parameter_names<'a>(
    function: Node<'a>,
    source: &'a [u8],
    wanted_type: &str,
) -> Option<Vec<&'a str>> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut names = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        let Ok(type_text) = type_node.utf8_text(source) else {
            continue;
        };
        if type_text.trim() != wanted_type {
            continue;
        }
        let declaration = parameter.utf8_text(source).ok()?.trim();
        let prefix = declaration.strip_suffix(type_text.trim())?.trim();
        names.extend(
            prefix
                .split(',')
                .map(str::trim)
                .filter(|name| is_identifier(name)),
        );
    }
    Some(names)
}

fn collect_handler_func_calls<'a>(node: Node<'a>, source: &'a [u8], out: &mut Vec<Node<'a>>) {
    if node.kind() == "call_expression"
        && call_text(node, source).is_some_and(|text| text.starts_with("http.HandlerFunc("))
    {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !is_function_like(child.kind()) {
            collect_handler_func_calls(child, source, out);
        }
    }
}

fn has_serve_http_call(text: &str, name: &str) -> bool {
    text.contains(&format!("{name}.ServeHTTP("))
}

fn has_terminal_response(text: &str) -> bool {
    [
        "http.Error(",
        "http.Redirect(",
        "http.NotFound(",
        ".WriteHeader(",
        ".Write(",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn receiver_method<'a>(call: Node<'a>, source: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let function = call.child_by_field_name("function")?;
    function.utf8_text(source).ok()?.trim().rsplit_once('.')
}

fn first_string_argument<'a>(call: Node<'a>, source: &'a [u8]) -> Option<String> {
    let argument = call.child_by_field_name("arguments")?.named_child(0)?;
    if argument.kind() != "interpreted_string_literal" {
        return None;
    }
    Some(argument.utf8_text(source).ok()?.to_owned())
}

fn call_text<'a>(call: Node<'a>, source: &'a [u8]) -> Option<&'a str> {
    call.utf8_text(source).ok().map(str::trim)
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    has_import_matching(root, source, |text| text.contains(&format!("\"{path}")))
}

fn has_import_prefix(root: Node, source: &[u8], prefix: &str) -> bool {
    has_import_matching(root, source, |text| {
        text.split('"')
            .nth(1)
            .is_some_and(|path| path.starts_with(prefix))
    })
}

fn has_import_matching(root: Node, source: &[u8], matches: impl Fn(&str) -> bool + Copy) -> bool {
    if root.kind() == "import_spec" && root.utf8_text(source).is_ok_and(matches) {
        return true;
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|child| has_import_matching(child, source, matches))
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

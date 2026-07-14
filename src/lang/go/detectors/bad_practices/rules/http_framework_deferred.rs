//! Deferred HTTP/framework rules with explicit import and lifetime gates.
//!
//! These rules deliberately stop at a function boundary. They do not attempt
//! to prove what a helper does with a context after it receives one, and they
//! only report a goroutine that directly references a framework context value.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-111: a Gin context is used from a goroutine without first switching the
/// goroutine to a copied context value.
pub(crate) fn detect_bp_111_gin_context_in_goroutine(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    detect_framework_context_across_goroutine(
        unit,
        out,
        "github.com/gin-gonic/gin",
        "Context",
        &crate::lang::go::detectors::bad_practices::BP_111_META,
        "Gin context is used from a goroutine without a local c.Copy() boundary",
    );
}

/// BP-119: a Fiber context is used from a goroutine after the request handler
/// has handed that work to another execution path.
pub(crate) fn detect_bp_119_fiber_context_in_goroutine(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    detect_framework_context_across_goroutine(
        unit,
        out,
        "github.com/gofiber/fiber",
        "Ctx",
        &crate::lang::go::detectors::bad_practices::BP_119_META,
        "Fiber context is used from a goroutine; copy request data before launching background work",
    );
}

fn detect_framework_context_across_goroutine(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    import_path: &str,
    context_type: &str,
    metadata: &crate::rules::RuleMetadata,
    message: &str,
) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let aliases = imported_aliases(root, source, import_path);
    if aliases.is_empty() {
        return;
    }

    walk_functions(
        root,
        source,
        unit,
        out,
        &aliases,
        context_type,
        metadata,
        message,
    );
}

fn walk_functions(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    aliases: &[String],
    context_type: &str,
    metadata: &crate::rules::RuleMetadata,
    message: &str,
) {
    if is_function_like(node.kind()) {
        inspect_function(
            node,
            source,
            unit,
            out,
            aliases,
            context_type,
            metadata,
            message,
        );
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(
            child,
            source,
            unit,
            out,
            aliases,
            context_type,
            metadata,
            message,
        );
    }
}

fn inspect_function(
    function: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    aliases: &[String],
    context_type: &str,
    metadata: &crate::rules::RuleMetadata,
    message: &str,
) {
    let Some(context_names) = context_parameter_names(function, source, aliases, context_type)
    else {
        return;
    };
    if context_names.is_empty() {
        return;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return;
    };

    collect_goroutines(body, source, &context_names, &mut |goroutine| {
        if goroutine_uses_context(goroutine, source, &context_names) {
            push_at(unit, out, metadata, goroutine.start_byte(), message);
        }
    });
}

fn collect_goroutines(
    node: Node,
    source: &[u8],
    context_names: &[String],
    inspect: &mut dyn FnMut(Node),
) {
    if node.kind() == "go_statement" {
        inspect(node);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // A nested closure has a separate local lifetime; do not attribute
        // its goroutines to the enclosing handler.
        if is_function_like(child.kind()) {
            continue;
        }
        collect_goroutines(child, source, context_names, inspect);
    }
}

fn goroutine_uses_context(go_statement: Node, source: &[u8], context_names: &[String]) -> bool {
    if goroutine_parameters_shadow_context(go_statement, source, context_names) {
        return false;
    }
    let Some(scope) = goroutine_scope(go_statement) else {
        return false;
    };

    // A local declaration or closure parameter shadows the handler context.
    // Suppressing the whole statement is conservative but avoids claiming
    // that a same-named local is the request context.
    if context_names
        .iter()
        .any(|name| scope_declares_name(scope, source, name))
    {
        return false;
    }

    contains_context_identifier(scope, source, context_names)
}

fn goroutine_parameters_shadow_context(
    go_statement: Node,
    source: &[u8],
    context_names: &[String],
) -> bool {
    fn find_func_literal(node: Node) -> Option<Node> {
        if node.kind() == "func_literal" {
            return Some(node);
        }
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find_map(find_func_literal)
    }

    let Some(function) = find_func_literal(go_statement) else {
        return false;
    };
    let Some(parameters) = function.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    parameters.named_children(&mut cursor).any(|parameter| {
        parameter
            .utf8_text(source)
            .ok()
            .and_then(|text| text.split_whitespace().next())
            .is_some_and(|name| context_names.iter().any(|context| context == name))
    })
}

fn goroutine_scope(go_statement: Node) -> Option<Node> {
    let mut stack = vec![go_statement];
    while let Some(node) = stack.pop() {
        if node.kind() == "func_literal" {
            return node.child_by_field_name("body");
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    // `go work(c)` has no closure body, so the statement itself is the
    // lifetime-sensitive scope and its argument list is still checked.
    Some(go_statement)
}

fn scope_declares_name(scope: Node, source: &[u8], wanted: &str) -> bool {
    fn visit(node: Node, source: &[u8], wanted: &str, scope: Node) -> bool {
        if node.id() != scope.id() && is_function_like(node.kind()) {
            return false;
        }

        if matches!(node.kind(), "short_var_declaration" | "var_spec")
            && declaration_names(node, source)
                .iter()
                .any(|name| name == wanted)
        {
            return true;
        }

        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| visit(child, source, wanted, scope))
    }

    visit(scope, source, wanted, scope)
}

fn declaration_names(node: Node, source: &[u8]) -> Vec<String> {
    let Ok(text) = node.utf8_text(source) else {
        return Vec::new();
    };
    let left = text
        .split_once(":=")
        .or_else(|| text.split_once('='))
        .map_or(text, |(left, _)| left);

    left.trim()
        .strip_prefix("var ")
        .unwrap_or(left.trim())
        .split(',')
        .map(str::trim)
        .map(|name| name.split_whitespace().next().unwrap_or(name))
        .filter(|name| !name.is_empty() && is_identifier(name))
        .map(str::to_owned)
        .collect()
}

fn contains_context_identifier(scope: Node, source: &[u8], context_names: &[String]) -> bool {
    fn visit(node: Node, source: &[u8], names: &[String], scope: Node) -> bool {
        if node.id() != scope.id() && is_function_like(node.kind()) {
            return false;
        }
        if node.kind() == "identifier"
            && node
                .utf8_text(source)
                .is_ok_and(|text| names.iter().any(|name| name == text))
        {
            return true;
        }

        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| visit(child, source, names, scope))
    }

    visit(scope, source, context_names, scope)
}

fn context_parameter_names(
    function: Node,
    source: &[u8],
    aliases: &[String],
    context_type: &str,
) -> Option<Vec<String>> {
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
        let type_text = type_text.trim();
        if !aliases
            .iter()
            .any(|alias| type_text == format!("*{alias}.{context_type}"))
        {
            continue;
        }

        let declaration = parameter.utf8_text(source).ok()?.trim();
        let prefix = declaration.strip_suffix(type_text)?.trim();
        names.extend(
            prefix
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty() && *name != "_")
                .filter(|name| is_identifier(name))
                .map(str::to_owned),
        );
    }

    Some(names)
}

fn imported_aliases(root: Node, source: &[u8], import_path: &str) -> Vec<String> {
    fn visit(node: Node, source: &[u8], import_path: &str, aliases: &mut Vec<String>) {
        if node.kind() == "import_spec"
            && let Ok(text) = node.utf8_text(source)
            && let Some(path) = quoted_import_path(text)
            && (path == import_path || path.starts_with(&format!("{import_path}/")))
        {
            let alias = text
                .split('"')
                .next()
                .map(str::trim)
                .filter(|prefix| !prefix.is_empty())
                .and_then(|prefix| prefix.split_whitespace().next())
                .filter(|prefix| *prefix != "." && *prefix != "_")
                .map(str::to_owned)
                .or_else(|| import_path.rsplit('/').next().map(str::to_owned));
            if let Some(alias) = alias {
                aliases.push(alias);
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(child, source, import_path, aliases);
        }
    }

    let mut aliases = Vec::new();
    visit(root, source, import_path, &mut aliases);
    aliases.sort();
    aliases.dedup();
    aliases
}

fn quoted_import_path(text: &str) -> Option<&str> {
    let (_, rest) = text.split_once('"')?;
    rest.split_once('"').map(|(path, _)| path)
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

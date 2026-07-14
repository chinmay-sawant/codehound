//! Phase 4 HTTP/framework candidates with explicit framework and handler gates.
//!
//! The generic BP-1 rule covers discarded errors in assignments. These rules
//! cover the framework-specific form that is easy to miss: a known bind or
//! body-parser method is used as a bare expression statement, so its returned
//! error is silently discarded.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-110: a Gin bind error is discarded as a bare expression statement.
pub(crate) fn detect_bp_110_gin_bind_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let rule = FrameworkRule {
        import_path: "github.com/gin-gonic/gin",
        context_type: "*gin.Context",
        methods: &["ShouldBindJSON", "ShouldBind"],
        metadata: &crate::lang::go::detectors::bad_practices::BP_110_META,
        message: "Gin binding error is discarded; check the bind result before using the request",
    };
    detect_ignored_framework_call(unit, out, &rule);
}

/// BP-117: an Echo bind error is discarded as a bare expression statement.
pub(crate) fn detect_bp_117_echo_bind_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let rule = FrameworkRule {
        import_path: "github.com/labstack/echo",
        context_type: "echo.Context",
        methods: &["Bind"],
        metadata: &crate::lang::go::detectors::bad_practices::BP_117_META,
        message: "Echo bind error is discarded; check the bind result before using the request",
    };
    detect_ignored_framework_call(unit, out, &rule);
}

/// BP-120: a Fiber body-parser error is discarded as a bare expression
/// statement.
pub(crate) fn detect_bp_120_fiber_body_parser_error_ignored(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let rule = FrameworkRule {
        import_path: "github.com/gofiber/fiber",
        context_type: "*fiber.Ctx",
        methods: &["BodyParser"],
        metadata: &crate::lang::go::detectors::bad_practices::BP_120_META,
        message: "Fiber body-parser error is discarded; check the parser result before using the request",
    };
    detect_ignored_framework_call(unit, out, &rule);
}

struct FrameworkRule<'a> {
    import_path: &'a str,
    context_type: &'a str,
    methods: &'a [&'a str],
    metadata: &'a crate::rules::RuleMetadata,
    message: &'a str,
}

fn detect_ignored_framework_call(unit: &ParsedUnit, out: &mut Vec<Finding>, rule: &FrameworkRule) {
    let source = unit.source.as_bytes();
    let root = unit.tree.root_node();
    if !has_import(root, source, rule.import_path) {
        return;
    }
    walk_functions(root, source, unit, out, rule);
}

fn walk_functions(
    node: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    rule: &FrameworkRule,
) {
    if is_function_like(node.kind()) {
        inspect_function(node, source, unit, out, rule);
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_functions(child, source, unit, out, rule);
    }
}

fn inspect_function(
    function: Node,
    source: &[u8],
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    rule: &FrameworkRule,
) {
    let Some(contexts) = parameter_names(function, source, rule.context_type) else {
        return;
    };
    if contexts.is_empty() {
        return;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return;
    };

    let mut emit = |call: Node| {
        push_at(unit, out, rule.metadata, call.start_byte(), rule.message);
    };
    collect_ignored_calls(body, source, &contexts, rule.methods, &mut emit);
}

fn collect_ignored_calls(
    node: Node,
    source: &[u8],
    contexts: &[&str],
    methods: &[&str],
    mut emit: &mut dyn FnMut(Node),
) {
    if node.kind() == "call_expression"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "expression_statement")
        && method_call(node, source).is_some_and(|(receiver, method)| {
            contexts.contains(&receiver) && methods.contains(&method)
        })
    {
        emit(node);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if is_function_like(child.kind()) {
            continue;
        }
        collect_ignored_calls(child, source, contexts, methods, &mut emit);
    }
}

fn parameter_names<'a>(
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
                .filter(|name| !name.is_empty() && *name != "_")
                .filter(|name| name.chars().all(is_identifier_char)),
        );
    }

    Some(names)
}

fn method_call<'a>(call: Node<'a>, source: &'a [u8]) -> Option<(&'a str, &'a str)> {
    let function = call.child_by_field_name("function")?;
    let text = function.utf8_text(source).ok()?.trim();
    text.rsplit_once('.')
}

fn has_import(root: Node, source: &[u8], path: &str) -> bool {
    if root.kind() == "import_spec"
        && root
            .utf8_text(source)
            .is_ok_and(|text| text.contains(&format!("\"{path}")))
    {
        return true;
    }

    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|child| has_import(child, source, path))
}

fn is_function_like(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

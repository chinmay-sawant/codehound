//! Curated BP-66+ core-language correctness rules.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-73: a function-local map is indexed before it is initialized.
///
/// The detector deliberately handles only the mechanically provable case:
/// a local `var name map[...]` declaration followed by an index assignment in
/// the same function, with no visible `make` assignment before the write.
pub(crate) fn detect_bp_73_nil_map_write_without_initialization(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_bytes();
    walk(unit.tree.root_node(), source, unit, out);
}

fn walk(node: Node, source: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>) {
    if node.kind() == "var_declaration"
        && let Some(function) = enclosing_function(node)
        && let Ok(text) = node.utf8_text(source)
        && let Some(name) = local_map_name(text)
        && let Some(body) = function.child_by_field_name("body")
    {
        let body_text = body.utf8_text(source).unwrap_or_default();
        let declaration_end = node.end_byte().saturating_sub(body.start_byte());
        let after_declaration = body_text.get(declaration_end..).unwrap_or_default();
        if let Some(write_offset) = index_write_offset(after_declaration, &name)
            && !initialized_before_write(after_declaration, &name, write_offset)
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_73_META,
                body.start_byte()
                    + node.end_byte().saturating_sub(body.start_byte())
                    + write_offset,
                "map is indexed before the local zero-value map is initialized with make",
            );
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(child, source, unit, out);
    }
}

fn enclosing_function(mut node: Node) -> Option<Node> {
    while let Some(parent) = node.parent() {
        // Keep the heuristic function-local. A map declared inside a closure
        // belongs to that closure, not to the surrounding declaration.
        if parent.kind() == "func_literal" {
            return None;
        }
        if matches!(parent.kind(), "function_declaration" | "method_declaration") {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn local_map_name(text: &str) -> Option<String> {
    let rest = text.trim().strip_prefix("var ")?;
    let mut parts = rest.split_whitespace();
    let name = parts.next()?;
    let declaration = parts.next()?;
    (declaration.starts_with("map[") && !text.contains('=')).then(|| name.into())
}

fn index_write_offset(source: &str, name: &str) -> Option<usize> {
    let needle = format!("{name}[");
    source.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let offset = line.len() - trimmed.len();
        trimmed
            .strip_prefix(&needle)
            .and_then(|rest| rest.find("] =").map(|_| offset))
            .map(|offset| source.find(line).unwrap_or(0) + offset)
    })
}

fn initialized_before_write(source: &str, name: &str, write_offset: usize) -> bool {
    let prefix = &source[..write_offset];
    prefix.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with(&format!("{name} := make(map"))
            || trimmed.starts_with(&format!("{name} = make(map"))
    })
}

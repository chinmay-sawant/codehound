//! Source snippets for diagnostics.

use tree_sitter::Node;

/// Up to 200 bytes of source at `node`.
pub fn snippet_of<'a>(src: &'a str, node: Node) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte().min(start + 200);
    src.get(start..end).unwrap_or("")
}

//! Python AST predicates.

use tree_sitter::Node;

pub fn is_re_compile_call(node: Node, src: &[u8]) -> bool {
    let text = node.utf8_text(src).unwrap_or("");
    text.contains("compile(") && (text.contains("re.compile") || text.ends_with(".compile("))
}

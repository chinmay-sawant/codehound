//! Generic AST walks.

use tree_sitter::Node;

/// Visit every node whose kind is in `kinds`.
pub fn walk_nodes<F: FnMut(Node)>(node: Node, kinds: &[&str], f: &mut F) {
    if kinds.contains(&node.kind()) {
        f(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_nodes(child, kinds, f);
    }
}

/// Visit call nodes (Go: `call_expression`, Python/TS: `call`, etc.).
pub fn walk_calls<F: FnMut(Node)>(node: Node, f: &mut F) {
    walk_nodes(node, &["call_expression", "call"], f);
}

/// Visit assignment-like nodes.
pub fn walk_assignments<F: FnMut(Node)>(node: Node, f: &mut F) {
    walk_nodes(
        node,
        &["assignment_statement", "short_var_declaration"],
        f,
    );
}

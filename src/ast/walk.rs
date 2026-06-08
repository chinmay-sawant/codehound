//! Generic AST walks.

use tree_sitter::Node;

/// Visit every node whose kind is in `kinds`.
pub fn walk_nodes<F: FnMut(Node)>(root: Node, kinds: &[&str], f: &mut F) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if kinds.contains(&node.kind()) {
            f(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Visit call nodes (Go: `call_expression`, Python/TS: `call`, etc.).
pub fn walk_calls<F: FnMut(Node)>(node: Node, f: &mut F) {
    walk_nodes(node, &["call_expression", "call"], f)
}

/// Visit assignment-like nodes.
pub fn walk_assignments<F: FnMut(Node)>(node: Node, f: &mut F) {
    walk_nodes(node, &["assignment_statement", "short_var_declaration"], f)
}

/// Walk a tree once, invoking `f` for both call and assignment nodes.
///
/// This is equivalent to two separate [`walk_calls`] + [`walk_assignments`]
/// traversals fused into one, so the closure runs at most once per node.
/// Use [`Node::kind`] inside the closure to dispatch on the matched kind.
pub fn walk_calls_and_assignments<F: FnMut(Node)>(root: Node, f: &mut F) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        match node.kind() {
            "call_expression" | "call" | "assignment_statement" | "short_var_declaration" => {
                f(node)
            }
            _ => {}
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

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
pub fn walk_calls_and_assignments<F: FnMut(Node)>(node: Node, f: &mut F) {
    match node.kind() {
        "call_expression" | "call" | "assignment_statement" | "short_var_declaration" => f(node),
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_calls_and_assignments(child, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_go(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("load go grammar");
        parser.parse(source, None).expect("parse go source")
    }

    fn parse_python(source: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("load python grammar");
        parser.parse(source, None).expect("parse python source")
    }

    #[test]
    fn walk_calls_and_assignments_finds_both_kinds_in_go() {
        let tree = parse_go(
            r#"
package main
func main() {
    a := foo(1, 2)
    b, c := 2, 3
    d = 4
    bar(a)
}
"#,
        );
        let mut calls = 0;
        let mut assignments = 0;
        walk_calls_and_assignments(tree.root_node(), &mut |node| match node.kind() {
            "call_expression" => calls += 1,
            "assignment_statement" | "short_var_declaration" => assignments += 1,
            _ => {}
        });
        assert_eq!(calls, 2, "expected foo(1,2) and bar(a), got {calls}");
        assert_eq!(assignments, 3, "expected a, b/c, d, got {assignments}");
    }

    #[test]
    fn walk_calls_and_assignments_finds_call_in_python() {
        let tree = parse_python(
            r#"
import re
x = 1
y = re.compile("x").match("y")
"#,
        );
        let mut calls = 0;
        let mut others = 0;
        walk_calls_and_assignments(tree.root_node(), &mut |node| match node.kind() {
            "call" => calls += 1,
            _ => others += 1,
        });
        assert!(calls >= 2, "expected >= 2 calls, got {calls}");
        // Python uses `expression_statement` for bare assignment, not
        // `assignment_statement` — we only visit `call` here, so
        // non-call visits are zero. The point is the `call` arm fires.
        assert_eq!(others, 0, "expected no other visits, got {others}");
    }

    #[test]
    fn walk_calls_and_assignments_visits_each_node_once() {
        // Verify the fused walk doesn't visit any node more than once.
        let tree = parse_go(
            r#"
package main
func main() {
    x := bar()
    y := baz(x)
}
"#,
        );
        let mut count = 0;
        walk_calls_and_assignments(tree.root_node(), &mut |_| count += 1);
        // Exactly 2 calls + 2 short_var_declarations = 4.
        assert_eq!(count, 4, "expected 4 matched nodes, got {count}");
    }
}

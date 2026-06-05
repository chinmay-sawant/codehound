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
    walk_nodes(node, &["assignment_statement", "short_var_declaration"], f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parse_go(source: &str) -> (Vec<u8>, tree_sitter::Tree) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("load go grammar");
        let tree = parser.parse(source, None).expect("parse go source");
        (source.as_bytes().to_vec(), tree)
    }

    fn parse_python(source: &str) -> (Vec<u8>, tree_sitter::Tree) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("load python grammar");
        let tree = parser.parse(source, None).expect("parse python source");
        (source.as_bytes().to_vec(), tree)
    }

    #[test]
    fn walk_calls_finds_call_expressions_in_go() {
        let (src, tree) = parse_go(
            r#"
package main
func main() {
    a := foo(1, 2)
    b := bar(a)
}
"#,
        );
        let mut texts: Vec<String> = Vec::new();
        walk_calls(tree.root_node(), &mut |n| {
            if let Ok(t) = n.utf8_text(&src) {
                texts.push(t.to_string());
            }
        });
        assert!(texts.iter().any(|c| c.contains("foo(1, 2)")), "got {texts:?}");
        assert!(texts.iter().any(|c| c.contains("bar(a)")), "got {texts:?}");
    }

    #[test]
    fn walk_calls_finds_call_nodes_in_python() {
        let (_src, tree) = parse_python(
            r#"
import re
def f():
    return re.compile("x").match("y")
"#,
        );
        let mut count = 0usize;
        walk_calls(tree.root_node(), &mut |_| count += 1);
        assert!(count >= 2, "expected at least 2 calls, got {count}");
    }

    #[test]
    fn walk_assignments_finds_short_var_decls() {
        let (_src, tree) = parse_go(
            r#"
package main
func main() {
    a := 1
    b, c := 2, 3
    d = 4
}
"#,
        );
        let mut count = 0usize;
        walk_assignments(tree.root_node(), &mut |_| count += 1);
        assert_eq!(count, 3, "expected 3 assignments (a, b/c, d), got {count}");
    }

    #[test]
    fn walk_nodes_filters_to_specified_kinds() {
        let (_src, tree) = parse_go("package main\nfunc main() { a := 1; b(a) }\n");
        let mut ids = Vec::new();
        walk_nodes(
            tree.root_node(),
            &["identifier", "call_expression"],
            &mut |n| ids.push(n.kind().to_string()),
        );
        assert!(ids.iter().all(|k| k == "identifier" || k == "call_expression"));
        assert!(!ids.is_empty(), "expected at least one match");
    }

    #[test]
    fn walk_nodes_does_not_call_f_for_unmatched_kinds() {
        let (_src, tree) = parse_go("package main\n");
        let mut count = 0usize;
        walk_nodes(tree.root_node(), &["nonexistent_kind"], &mut |_| count += 1);
        assert_eq!(count, 0);
    }
}

#![cfg(feature = "go")]

use slopguard::ast::walk_nodes;
use tree_sitter::Parser;

fn parse_go(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("load go grammar");
    parser.parse(source, None).expect("parse go source")
}

#[test]
fn walk_nodes_finds_both_kinds_in_go() {
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
    walk_nodes(
        tree.root_node(),
        &[
            "call_expression",
            "assignment_statement",
            "short_var_declaration",
        ],
        &mut |node| match node.kind() {
            "call_expression" => calls += 1,
            "assignment_statement" | "short_var_declaration" => assignments += 1,
            _ => {}
        },
    );
    assert_eq!(calls, 2, "expected foo(1,2) and bar(a), got {calls}");
    assert_eq!(assignments, 3, "expected a, b/c, d, got {assignments}");
}

#[test]
fn walk_nodes_visits_each_node_once() {
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
    walk_nodes(
        tree.root_node(),
        &[
            "call_expression",
            "assignment_statement",
            "short_var_declaration",
        ],
        &mut |_| count += 1,
    );
    assert_eq!(count, 4, "expected 4 matched nodes, got {count}");
}

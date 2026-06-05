#![cfg(any(feature = "go", feature = "python"))]

use slopguard::ast::walk_calls_and_assignments;
use tree_sitter::Parser;

#[cfg(feature = "go")]
fn parse_go(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("load go grammar");
    parser.parse(source, None).expect("parse go source")
}

#[cfg(feature = "python")]
fn parse_python(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("load python grammar");
    parser.parse(source, None).expect("parse python source")
}

#[cfg(feature = "go")]
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

#[cfg(feature = "python")]
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
    assert_eq!(others, 0, "expected no other visits, got {others}");
}

#[cfg(feature = "go")]
#[test]
fn walk_calls_and_assignments_visits_each_node_once() {
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
    assert_eq!(count, 4, "expected 4 matched nodes, got {count}");
}

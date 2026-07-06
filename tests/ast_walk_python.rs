#![cfg(feature = "python")]

use slopguard::ast::walk_nodes;
use tree_sitter::Parser;

fn parse_python(source: &str) -> tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("load python grammar");
    parser.parse(source, None).expect("parse python source")
}

#[test]
fn walk_nodes_finds_call_in_python() {
    let tree = parse_python(
        r#"
import re
x = 1
y = re.compile("x").match("y")
"#,
    );
    let mut calls = 0;
    let mut others = 0;
    walk_nodes(tree.root_node(), &["call"], &mut |node| match node.kind() {
        "call" => calls += 1,
        _ => others += 1,
    });
    assert!(calls >= 2, "expected >= 2 calls, got {calls}");
    assert_eq!(others, 0, "expected no other visits, got {others}");
}
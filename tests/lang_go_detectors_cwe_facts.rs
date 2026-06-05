#![cfg(feature = "go")]

use std::path::Path;
use std::sync::Arc;

use tree_sitter::Parser;

use slopguard::core::{LanguagePlugin, LanguageId, ParsedUnit};
use slopguard::lang::go::GoPlugin;
use slopguard::lang::go::detectors::cwe::facts::*;

fn parse_go_source(source: &str) -> ParsedUnit {
    let plugin = GoPlugin;
    let mut parser = Parser::new();
    plugin.configure_parser(&mut parser);
    plugin
        .parse_with(&mut parser, Path::new("sample.go"), Arc::from(source))
        .expect("parse go source")
}

#[test]
fn fact_builder_extracts_input_bindings_and_calls() {
    let unit = parse_go_source(
        r#"
package sample

import "net/http"

func Handle(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("path")
    mode := r.Header.Get("X-Mode")
    _ = path
    _ = mode
    http.Get(path)
}
"#,
    );

    let facts = build_go_unit_facts(&unit);

    assert!(facts
        .input_bindings
        .iter()
        .any(|binding| { binding.name == "path" && binding.kind == InputKind::UserControlled }));
    assert!(facts
        .input_bindings
        .iter()
        .any(|binding| { binding.name == "mode" && binding.kind == InputKind::UserControlled }));
    assert!(facts.call_facts.iter().any(|call| {
        call.callee == "http.Get" && call.arguments.iter().any(|arg| arg == "path")
    }));
}

#[test]
fn fact_builder_marks_trusted_config_assignments() {
    let unit = parse_go_source(
        r#"
package sample

import "os"

func Build() string {
    billingAPI := os.Getenv("BILLING_API_URL")
    return billingAPI
}
"#,
    );

    let facts = build_go_unit_facts(&unit);

    assert!(facts.input_bindings.iter().any(|binding| {
        binding.name == "billingAPI" && binding.kind == InputKind::TrustedConfig
    }));
    assert!(facts
        .assignments
        .iter()
        .any(|assignment| assignment.name == "billingAPI"
            && assignment.expr.contains("os.Getenv")));
}

#[test]
fn split_assignment_handles_both_forms() {
    assert_eq!(
        split_assignment("a := b"),
        Some(("a", "b"))
    );
    assert_eq!(
        split_assignment("a = b"),
        Some(("a", "b"))
    );
    assert_eq!(split_assignment("a"), None);
    assert_eq!(
        split_assignment("a, b := 1, 2"),
        Some(("a, b", "1, 2"))
    );
}

#[test]
fn extract_identifiers_handles_empty_and_multi() {
    assert_eq!(extract_identifiers(""), Vec::<&str>::new());
    assert_eq!(extract_identifiers("a"), vec!["a"]);
    assert_eq!(extract_identifiers("a, b, c"), vec!["a", "b", "c"]);
    assert_eq!(extract_identifiers("  a  ,  b  "), vec!["a", "b"]);
}

#[test]
fn is_user_input_expr_matches_common_patterns() {
    assert!(is_user_input_expr(r#"r.URL.Query().Get("x")"#));
    assert!(is_user_input_expr(r#"c.PostForm("x")"#));
    assert!(is_user_input_expr("io.ReadAll(r.Body)"));
    assert!(!is_user_input_expr(r#"os.Getenv("X")"#));
    assert!(!is_user_input_expr("42"));
}

#[test]
fn build_facts_survives_random_input() {
    let mut state: u64 = 0x1234_5678_DEAD_BEEF;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("load go grammar");
    for _ in 0..256 {
        let len = (next() as usize) % 512;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push((next() & 0xFF) as u8);
        }
        let source = std::str::from_utf8(&bytes).unwrap_or("");
        if let Some(tree) = parser.parse(source, None) {
            let unit = ParsedUnit {
                language: LanguageId::Go,
                display_path: String::from("fuzz.go"),
                path: std::path::PathBuf::from("fuzz.go"),
                source: Arc::from(source),
                tree,
                line_starts: compute_line_starts_for(source),
            };
            let _ = build_go_unit_facts(&unit);
        }
    }
}

fn compute_line_starts_for(source: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

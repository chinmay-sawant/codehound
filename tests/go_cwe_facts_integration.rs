//! Go CWE fact extraction tests.

use std::path::Path;
use std::sync::Arc;

use slopguard::core::LanguagePlugin;
use slopguard::lang::go::detectors::cwe::facts::{build_go_unit_facts, InputKind};
use slopguard::lang::go::GoPlugin;

fn parse_go_source(source: &str) -> slopguard::core::ParsedUnit {
    let plugin = GoPlugin;
    let mut parser = tree_sitter::Parser::new();
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

    assert!(facts.input_bindings.iter().any(|binding| {
        binding.name == "path" && binding.kind == InputKind::UserControlled
    }));
    assert!(facts.input_bindings.iter().any(|binding| {
        binding.name == "mode" && binding.kind == InputKind::UserControlled
    }));
    assert!(facts
        .call_facts
        .iter()
        .any(|call| call.callee == "http.Get" && call.arguments.iter().any(|arg| arg == "path")));
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
        .any(|assignment| assignment.name == "billingAPI" && assignment.expr.contains("os.Getenv")));
}

//! Fact extraction for Go CWE heuristics.
//!
//! These types are internal to the Go CWE detector bundle. Library consumers
//! see only the `Finding` they produce; the IR lives behind `pub(crate)`.

use crate::ast::walk_calls_and_assignments;
use crate::core::ParsedUnit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputKind {
    UserControlled,
    TrustedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InputBinding {
    pub name: String,
    pub kind: InputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallFact {
    pub callee: String,
    pub arguments: Vec<String>,
    pub start_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignmentFact {
    pub name: String,
    pub expr: String,
    pub start_byte: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct GoUnitFacts {
    pub input_bindings: Vec<InputBinding>,
    pub call_facts: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
}

pub(crate) fn build_go_unit_facts(unit: &ParsedUnit) -> GoUnitFacts {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut facts = GoUnitFacts::default();

    walk_calls_and_assignments(root, &mut |node| match node.kind() {
        "call_expression" | "call" => {
            let Some(func) = node.child_by_field_name("function") else {
                return;
            };
            let Ok(callee) = func.utf8_text(src) else {
                return;
            };

            let arguments = node
                .child_by_field_name("arguments")
                .map(|args| extract_argument_texts(args, src))
                .unwrap_or_default();

            facts.call_facts.push(CallFact {
                callee: callee.to_string(),
                arguments,
                start_byte: node.start_byte(),
            });
        }
        "assignment_statement" | "short_var_declaration" => {
            let Ok(text) = node.utf8_text(src) else {
                return;
            };
            let Some((lhs, rhs)) = split_assignment(text) else {
                return;
            };
            let names = extract_identifiers(lhs);
            if names.is_empty() {
                return;
            }
            let kind = if is_user_input_expr(rhs) {
                Some(InputKind::UserControlled)
            } else if is_trusted_config_expr(rhs) {
                Some(InputKind::TrustedConfig)
            } else {
                None
            };
            if let Some(kind) = kind {
                for name in &names {
                    facts.input_bindings.push(InputBinding {
                        name: (*name).to_string(),
                        kind,
                    });
                }
            }

            for name in names {
                facts.assignments.push(AssignmentFact {
                    name: name.to_string(),
                    expr: rhs.to_string(),
                    start_byte: node.start_byte(),
                });
            }
        }
        _ => {}
    });

    facts
}

fn extract_argument_texts(args_node: tree_sitter::Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(text.trim().to_string());
        }
    }
    out
}

fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

fn is_user_input_expr(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
        || expr.contains(".GetHeader(")
        || expr.contains(".Header.Get(")
        || expr.contains(".GetRawData(")
        || expr.contains("io.ReadAll(r.Body)")
}

fn is_trusted_config_expr(expr: &str) -> bool {
    expr.contains("os.Getenv(") || expr.contains("os.LookupEnv(")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::LanguagePlugin;
    use crate::lang::go::GoPlugin;
    use std::path::Path;
    use std::sync::Arc;
    use tree_sitter::Parser;

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

    /// In-process fuzz harness: feed the parser 256 random byte sequences
    /// and assert that `build_go_unit_facts` never panics. This is a
    /// cheap stand-in for `cargo-fuzz` (which requires nightly).
    #[test]
    fn build_facts_survives_random_input() {
        // Tiny xorshift PRNG so the test is deterministic.
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
                    language: crate::core::LanguageId::Go,
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
}

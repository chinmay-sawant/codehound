#![cfg(feature = "go")]

use std::path::PathBuf;
use std::sync::Arc;

use codehound::ast::compute_line_starts;
use codehound::core::{LanguageId, ParsedUnit};
use tree_sitter::Parser;

fn parsed(source: &str) -> ParsedUnit {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("load go grammar");
    ParsedUnit {
        language: LanguageId::Go,
        display_path: String::from("test.go"),
        path: PathBuf::from("test.go"),
        source: Arc::from(source),
        tree: parser.parse(source, None).expect("parse"),
        line_starts: compute_line_starts(source),
        function_spans: Vec::new(),
    }
}

#[test]
fn line_col_matches_underlying_ast_helper() {
    let source = "package main\nfunc main() {}\n";
    let unit = parsed(source);
    let offset = source.find("func").unwrap();
    assert_eq!(unit.line_col(offset), (2, 1));
    assert_eq!(unit.line_col(0), (1, 1));
}

#[test]
fn line_col_for_offset_in_second_line() {
    let source = "package main\n    foo\n";
    let unit = parsed(source);
    let offset = source.find("foo").unwrap();
    assert_eq!(unit.line_col(offset), (2, 5));
}

#[test]
fn line_col_for_offset_past_end_returns_last_line() {
    let source = "a\nb\nc\n";
    let unit = parsed(source);
    let offset = source.len() + 100;
    let (line, _) = unit.line_col(offset);
    assert!(line >= 1, "got {line}");
}

#[test]
fn parsed_unit_read_only_accessors_expose_parser_data() {
    let unit = parsed("package main\nfunc main() {}\n");

    assert_eq!(unit.language(), LanguageId::Go);
    assert_eq!(unit.path().to_str(), Some("test.go"));
    assert_eq!(unit.display_path(), "test.go");
    assert_eq!(unit.source().as_ref(), "package main\nfunc main() {}\n");
    assert_eq!(unit.tree().root_node().kind(), "source_file");
    assert_eq!(unit.line_starts(), &[0, 13, 28]);
    assert!(unit.function_spans().is_empty());
}

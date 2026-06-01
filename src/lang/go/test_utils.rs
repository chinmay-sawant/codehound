//! Test helpers for Go detectors.

use std::sync::Arc;

use tree_sitter::Parser;

use crate::core::ParsedUnit;
use crate::lang::go::parser;

pub fn parse_snippet(src: &str) -> ParsedUnit {
    let mut p = Parser::new();
    parser::configure(&mut p);
    parser::parse_with(&mut p, "test.go".as_ref(), Arc::from(src))
        .expect("parse snippet")
}

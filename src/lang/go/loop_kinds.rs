//! Go loop node kinds (tree-sitter-go).
//!
//! Used by [`crate::ast::nearest_loop`] to find the nearest enclosing loop
//! when analysing call or assignment sites for the PERF detectors.

pub const LOOP_NODE_KINDS: &[&str] = &["for_statement"];

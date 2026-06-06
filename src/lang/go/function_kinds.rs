//! Go function-like node kinds (tree-sitter-go).
//!
//! Used by [`crate::ast::nearest_function`] and the analyzer's function-context
//! post-pass to resolve the enclosing function for each finding. In Go,
//! "function-like" covers both free functions and methods on a receiver type —
//! e.g. `func main()` and `func (p *PageManager) DrawTable(...)` are both
//! enclosed by the kinds listed below.

pub const FUNCTION_NODE_KINDS: &[&str] = &["function_declaration", "method_declaration"];

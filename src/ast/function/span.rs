//! `FunctionSpan` data type and the `enclosing_function` lookup.

use super::collect::FunctionSpan;

/// Find the smallest enclosing function for a 1-indexed `line`. Returns
/// `None` if no function spans that line (e.g. top-level statements in
/// Python, package-level var decls in Go, or line outside the parsed range).
pub fn enclosing_function(spans: &[FunctionSpan], line: usize) -> Option<&FunctionSpan> {
    spans
        .iter()
        .filter(|s| s.start_line <= line && line <= s.end_line)
        .max_by_key(|s| s.depth)
}

//! Shared tree-sitter AST helpers.

mod function;
mod location;
mod r#loop;
mod snippet;
mod walk;

pub use function::{FunctionSpan, collect_function_spans, enclosing_function, nearest_function};
pub use location::{compute_line_starts, line_col, line_col_with_starts};
pub use r#loop::nearest_loop;
pub use snippet::snippet_of;
pub use walk::{walk_assignments, walk_calls, walk_calls_and_assignments, walk_nodes};

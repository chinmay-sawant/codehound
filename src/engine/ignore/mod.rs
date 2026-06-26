//! Inline suppression comments.

mod apply;
mod directive;
mod parse;

pub use apply::{apply_file_ignore, apply_inline_ignores};
pub use directive::IgnoreDirective;
pub use parse::{parse_file_ignore, parse_inline_ignores};

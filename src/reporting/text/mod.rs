//! Plain-text reporter.

mod options;
mod render;
mod style;
mod summary;

pub use options::{TextOptions, print, print_with_options, print_without_snippet};
pub use render::write_with_options;

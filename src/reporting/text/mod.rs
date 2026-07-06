//! Plain-text reporter.

mod options;
mod render;
mod style;
mod summary;

pub use options::{TextOptions, print, print_with_options};
pub use render::write_with_options;

use crate::engine::AnalysisResult;
use crate::reporting::OutputReporter;
use crate::Error;

/// Reporter that renders findings as human-readable text.
pub struct TextReporter {
    pub options: TextOptions,
}

impl OutputReporter for TextReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        print_with_options(result, self.options)
    }
}

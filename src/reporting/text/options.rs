//! `TextOptions` type and the `print_with_options` entry point.

use std::io;

use crate::Error;
use crate::engine::AnalysisResult;

use super::render::write_with_options;

#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    pub color: bool,
    pub suppress_snippet: bool,
    pub show_fingerprint: bool,
    pub verbose: bool,
    pub debug_timing: bool,
}

/// Write a human-readable finding report with custom formatting options.
///
/// # Errors
///
/// Returns [`Error`] when formatting or stdout write fails.
#[must_use = "I/O errors from writing text output must be handled"]
pub(crate) fn print_with_options(
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<(), Error> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_with_options(&mut out, result, options)
}

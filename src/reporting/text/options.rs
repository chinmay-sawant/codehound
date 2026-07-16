//! `TextOptions` type and the `print_with_options` entry point.

use std::io;

use crate::Error;
use crate::engine::AnalysisResult;

use super::render::write_with_options;

/// Formatting knobs for the human-readable text reporter.
#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    /// Colorize severity and rule IDs when the terminal supports it.
    pub color: bool,
    /// Omit source snippets under each finding.
    pub suppress_snippet: bool,
    /// Print finding fingerprints in the text report.
    pub show_fingerprint: bool,
    /// Include extra scan statistics in the footer.
    pub verbose: bool,
    /// Print top detector timing after the report.
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

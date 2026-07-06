//! Plain-text reporter.

mod options;
mod render;
mod style;
mod summary;

pub use options::TextOptions;
pub use render::write_with_options;
pub use summary::write_no_terminal_summary;

use options::print_with_options;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::export::{ExportOptions, ExportSummary};
use crate::reporting::OutputReporter;

/// Reporter that renders findings as human-readable text.
pub struct TextReporter {
    pub options: TextOptions,
}

impl OutputReporter for TextReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        print_with_options(result, self.options)
    }
}

/// Summary-only text reporter for `--no-terminal` runs.
pub struct NoTerminalReporter {
    pub options: TextOptions,
    pub export_options: ExportOptions,
    pub export_summary: ExportSummary,
}

impl OutputReporter for NoTerminalReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        write_no_terminal_summary(
            &mut out,
            result,
            self.options,
            &self.export_options,
            &self.export_summary,
        )
    }
}

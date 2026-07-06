//! Output formatters.

pub mod json;
pub mod sarif;
pub mod text;

pub use json::JsonReporter;
pub use sarif::SarifReporter;
pub use text::TextReporter;

use crate::Error;
use crate::engine::AnalysisResult;

/// A reporter that serializes an [`AnalysisResult`] to a specific output
/// format. Each format is a unit or options struct implementing this trait.
pub trait OutputReporter {
    /// Write the report to stdout.
    fn report(&self, result: &AnalysisResult) -> Result<(), Error>;
}

//! SARIF 2.1.0 reporter.

mod entry;
mod log;
mod schema;

pub use entry::render_to_string;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::reporting::OutputReporter;

/// Reporter that serializes findings as SARIF 2.1.0 JSON.
pub struct SarifReporter {
    pub compact: bool,
}

impl OutputReporter for SarifReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        if self.compact {
            entry::print_compact(result)
        } else {
            entry::print(result)
        }
    }
}

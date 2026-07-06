//! SARIF 2.1.0 reporter.

mod entry;
mod log;
mod schema;
mod time;

pub use entry::{print, print_compact, render_to_string};

use crate::engine::AnalysisResult;
use crate::reporting::OutputReporter;
use crate::Error;

/// Reporter that serializes findings as SARIF 2.1.0 JSON.
pub struct SarifReporter {
    pub compact: bool,
}

impl OutputReporter for SarifReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        if self.compact {
            print_compact(result)
        } else {
            print(result)
        }
    }
}

//! JSON reporter.
//!
//! Two output modes:
//! - **NDJSON** (default): one finding per line, stream-friendly
//! - **Envelope** (`--json-envelope`): a single JSON object wrapping the
//!   run metadata + findings array

mod entry;
mod types;

pub use entry::print_envelope;
pub use types::{Envelope, FindingJson};

use crate::Error;
use crate::engine::AnalysisResult;
use crate::reporting::OutputReporter;

/// Reporter that serializes findings as NDJSON or a JSON envelope.
pub struct JsonReporter {
    pub envelope: bool,
}

impl OutputReporter for JsonReporter {
    fn report(&self, result: &AnalysisResult) -> Result<(), Error> {
        if self.envelope {
            print_envelope(result)
        } else {
            entry::print(result)
        }
    }
}

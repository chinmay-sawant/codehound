//! JSON entry points: `print` (NDJSON), `print_envelope`.

use std::io::Write;

use crate::Error;
use crate::engine::AnalysisResult;

use super::types::{Envelope, FindingJson};

/// Write findings as NDJSON (one JSON object per line) to stdout.
///
/// # Errors
///
/// Returns [`Error`] when JSON serialization or stdout write fails.
#[must_use = "I/O errors from writing JSON output must be handled"]
pub fn print(result: &AnalysisResult) -> Result<(), Error> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in &result.findings {
        let j = FindingJson::from(f);
        serde_json::to_writer(&mut out, &j)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// Write a versioned JSON envelope (metadata + findings) to stdout.
///
/// # Errors
///
/// Returns [`Error`] when JSON serialization or stdout write fails.
#[must_use = "I/O errors from writing JSON output must be handled"]
pub fn print_envelope(result: &AnalysisResult) -> Result<(), Error> {
    let envelope = Envelope::from(result);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &envelope)?;
    out.write_all(b"\n")?;
    Ok(())
}

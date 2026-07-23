//! SARIF entry points: `print`, `print_compact`, `render_to_string`.

use std::io::{self, Write};

use crate::Error;
use crate::engine::AnalysisResult;

use super::log::build_log;

/// Write a SARIF log to stdout.
///
/// # Errors
///
/// Returns [`Error`] when SARIF serialization or stdout write fails.
#[must_use = "I/O errors from writing SARIF output must be handled"]
pub(crate) fn write_log(result: &AnalysisResult, compact: bool) -> Result<(), Error> {
    let log = build_log(result)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if compact {
        serde_json::to_writer(&mut out, &log)?;
    } else {
        serde_json::to_writer_pretty(&mut out, &log)?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

/// Write a pretty-printed SARIF log to stdout.
pub(crate) fn print(result: &AnalysisResult) -> Result<(), Error> {
    write_log(result, false)
}

/// Write a compact (single-line) SARIF log to stdout.
pub(crate) fn print_compact(result: &AnalysisResult) -> Result<(), Error> {
    write_log(result, true)
}

#[doc(hidden)]
#[must_use = "SARIF serialization failures must be handled"]
///
/// # Errors
///
/// Returns [`Error`] when the analysis result cannot be serialized as SARIF.
pub fn render_to_string(result: &AnalysisResult) -> Result<String, Error> {
    let log = build_log(result)?;
    serde_json::to_string_pretty(&log).map_err(Error::from)
}

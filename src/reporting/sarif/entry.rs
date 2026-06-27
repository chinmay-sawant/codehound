//! SARIF entry points: `print`, `print_compact`, `render_to_string`.

use std::io::{self, Write};

use crate::Error;
use crate::engine::AnalysisResult;

use super::log::build_log;

/// Write a pretty-printed SARIF log to stdout.
///
/// # Errors
///
/// Returns [`Error`] when SARIF serialization or stdout write fails.
#[must_use = "I/O errors from writing SARIF output must be handled"]
pub fn print(result: &AnalysisResult) -> Result<(), Error> {
    print_with(result, true)
}

/// Write a compact (single-line) SARIF log to stdout.
///
/// # Errors
///
/// Returns [`Error`] when SARIF serialization or stdout write fails.
#[must_use = "I/O errors from writing SARIF output must be handled"]
pub fn print_compact(result: &AnalysisResult) -> Result<(), Error> {
    print_with(result, false)
}

fn print_with(result: &AnalysisResult, pretty: bool) -> Result<(), Error> {
    let log = build_log(result);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if pretty {
        serde_json::to_writer_pretty(&mut out, &log)?;
    } else {
        serde_json::to_writer(&mut out, &log)?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

#[doc(hidden)]
#[must_use = "SARIF serialization failures must be handled"]
pub fn render_to_string(result: &AnalysisResult) -> Result<String, Error> {
    let log = build_log(result);
    let mut buf = Vec::new();
    serde_json::to_writer_pretty(&mut buf, &log)?;
    let s = String::from_utf8(buf)
        .map_err(|e| Error::Walk(format!("SARIF JSON is not valid UTF-8: {e}")))?;
    Ok(s)
}

//! SARIF entry points: `print`, `print_compact`, `render_to_string`.

use std::io::{self, Write};

use anyhow::Result;

use crate::engine::AnalysisResult;

use super::log::build_log;

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with(result, true)
}

pub fn print_compact(result: &AnalysisResult) -> Result<()> {
    print_with(result, false)
}

fn print_with(result: &AnalysisResult, pretty: bool) -> Result<()> {
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
pub fn render_to_string(result: &AnalysisResult) -> String {
    let log = build_log(result);
    let mut buf = Vec::new();
    serde_json::to_writer_pretty(&mut buf, &log).unwrap();
    String::from_utf8(buf).unwrap()
}

//! JSON reporter (newline-delimited, line-per-finding).

use std::io::Write;

use anyhow::Result;

use crate::engine::AnalysisResult;

pub fn print(result: &AnalysisResult) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in &result.findings {
        serde_json::to_writer(&mut out, f)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

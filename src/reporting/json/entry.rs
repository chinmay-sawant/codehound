//! JSON entry points: `print` (NDJSON), `print_envelope`.

use std::io::Write;

use anyhow::Result;

use crate::engine::AnalysisResult;

use super::types::{Envelope, FindingJson};

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_ndjson(result)
}

pub fn print_envelope(result: &AnalysisResult) -> Result<()> {
    let envelope = Envelope::from(result);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &envelope)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn print_ndjson(result: &AnalysisResult) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in &result.findings {
        let j = FindingJson::from(f);
        serde_json::to_writer(&mut out, &j)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

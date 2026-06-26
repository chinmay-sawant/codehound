//! `TextOptions` type and convenience entry points (`print`, `print_without_snippet`, `print_with_options`).

use std::io;

use anyhow::Result;

use crate::engine::AnalysisResult;

use super::render::write_with_options;

#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    pub suppress_snippet: bool,
    pub show_fingerprint: bool,
    pub verbose: bool,
    pub debug_timing: bool,
}

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with_options(result, TextOptions::default())
}

/// Like [`print`] but suppresses the source snippet block.
pub fn print_without_snippet(result: &AnalysisResult) -> Result<()> {
    print_with_options(
        result,
        TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
    )
}

pub fn print_with_options(result: &AnalysisResult, options: TextOptions) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_with_options(&mut out, result, options)
}

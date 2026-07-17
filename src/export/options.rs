//! `ExportOptions` and `ExportSummary`.

use std::path::PathBuf;

/// Options controlling on-disk finding context/chunk export.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Write one context file per finding.
    pub export_context: bool,
    /// Write chunked finding files.
    pub export_chunks: bool,
    /// Maximum number of findings per chunk file.
    pub chunk_size: usize,
    /// Directory for per-finding context files.
    pub context_output_dir: PathBuf,
    /// Directory for chunk files.
    pub chunks_output_dir: PathBuf,
}

/// Counts of files written by a successful export pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExportSummary {
    /// Number of context files written.
    pub context_files_written: usize,
    /// Number of chunk files written.
    pub chunk_files_written: usize,
}

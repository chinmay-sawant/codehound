//! `ExportOptions` and `ExportSummary`.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub export_context: bool,
    pub export_chunks: bool,
    pub chunk_size: usize,
    pub context_output_dir: PathBuf,
    pub chunks_output_dir: PathBuf,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExportSummary {
    pub context_files_written: usize,
    pub chunk_files_written: usize,
}

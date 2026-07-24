//! `export_findings`: dispatch to context-file and chunk-file writers.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::rules::Finding;

use super::chunk::{chunk_file_names, write_chunk_files_streaming};
use super::finding_block::format_finding_block;
use super::options::{ExportOptions, ExportSummary};
use super::owned::OutputStage;

/// Write per-finding context `.txt` files and/or chunked export files.
///
/// # Errors
///
/// Returns [`Error`] when directory creation, file removal, or file write fails.
#[must_use = "export I/O failures must be handled"]
pub fn export_findings(
    findings: &[Finding],
    options: &ExportOptions,
    source_cache: &HashMap<String, Arc<str>>,
) -> Result<ExportSummary, Error> {
    if !options.export_context && !options.export_chunks {
        return Ok(ExportSummary::default());
    }
    if options.export_context
        && options.export_chunks
        && output_dirs_match(&options.context_output_dir, &options.chunks_output_dir)?
    {
        return Err(Error::Config(
            "context and chunk exports must use different output directories".to_string(),
        ));
    }

    let total = findings.len();
    let mut file_cache = HashMap::<String, Option<String>>::new();
    let mut summary = ExportSummary::default();

    if options.export_context {
        let context_names = (1..=total).map(|index| format!("{index}.txt"));
        let stage = OutputStage::create(&options.context_output_dir, context_names)?;
        for (index, finding) in findings.iter().enumerate() {
            let text =
                format_finding_block(finding, index + 1, total, &mut file_cache, source_cache);
            let output_path = stage.path().join(format!("{}.txt", index + 1));
            fs::write(output_path, text)?;
            summary.context_files_written += 1;
        }
        stage.commit()?;
    }

    if options.export_chunks {
        let stage = OutputStage::create(
            &options.chunks_output_dir,
            chunk_file_names(findings.len(), options.chunk_size),
        )?;
        summary.chunk_files_written = write_chunk_files_streaming(
            findings,
            stage.path(),
            options.chunk_size.max(1),
            &mut file_cache,
            source_cache,
        )?;
        stage.commit()?;
    }

    Ok(summary)
}

fn output_dirs_match(left: &Path, right: &Path) -> Result<bool, Error> {
    fs::create_dir_all(left)?;
    fs::create_dir_all(right)?;
    Ok(fs::canonicalize(left)? == fs::canonicalize(right)?)
}

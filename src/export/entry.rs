//! `export_findings`: dispatch to context-file and chunk-file writers.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use anyhow::Result;

use crate::rules::Finding;

use super::chunk::{clean_matching_txt_files, write_chunk_files_streaming};
use super::finding_block::format_finding_block;
use super::options::{ExportOptions, ExportSummary};

pub fn export_findings(
    findings: &[Finding],
    options: &ExportOptions,
    source_cache: &HashMap<String, Arc<str>>,
) -> Result<ExportSummary> {
    if !options.export_context && !options.export_chunks {
        return Ok(ExportSummary::default());
    }

    let total = findings.len();
    let mut file_cache = HashMap::<String, Option<String>>::new();
    let mut summary = ExportSummary::default();

    if options.export_context {
        fs::create_dir_all(&options.context_output_dir)?;
        clean_matching_txt_files(&options.context_output_dir, |name| name.ends_with(".txt"))?;
        for (index, finding) in findings.iter().enumerate() {
            let text =
                format_finding_block(finding, index + 1, total, &mut file_cache, source_cache);
            let output_path = options
                .context_output_dir
                .join(format!("{}.txt", index + 1));
            fs::write(output_path, text)?;
            summary.context_files_written += 1;
        }
    }

    if options.export_chunks {
        summary.chunk_files_written = write_chunk_files_streaming(
            findings,
            &options.chunks_output_dir,
            options.chunk_size.max(1),
            &mut file_cache,
            source_cache,
        )?;
    }

    Ok(summary)
}

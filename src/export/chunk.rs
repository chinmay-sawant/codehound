//! Chunk-file writer: groups findings into `Chunk_X_Y.txt` files, plus
//! the `clean_matching_txt_files` helper.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;

use crate::Error;

use crate::rules::Finding;

use super::finding_block::format_finding_block;

pub(super) fn write_chunk_files_streaming(
    findings: &[Finding],
    output_dir: &Path,
    chunk_size: usize,
    file_cache: &mut HashMap<String, Option<String>>,
    source_cache: &HashMap<String, Arc<str>>,
) -> Result<usize, Error> {
    fs::create_dir_all(output_dir)?;
    clean_matching_txt_files(output_dir, |name| {
        name.starts_with("Chunk_") && name.ends_with(".txt")
    })?;

    if findings.is_empty() {
        return Ok(0);
    }

    let separator = "=".repeat(100);
    let total = findings.len();
    let mut chunk_count = 0;

    for (chunk_index, chunk) in findings.chunks(chunk_size).enumerate() {
        let start_index = chunk_index * chunk_size + 1;
        let end_index = start_index + chunk.len().saturating_sub(1);
        let path = output_dir.join(format!("Chunk_{start_index}_{end_index}.txt"));
        let mut writer = BufWriter::new(File::create(path)?);
        writeln!(writer, "Findings {start_index}-{end_index} of {total}")?;
        writeln!(writer)?;

        for (offset, finding) in chunk.iter().enumerate() {
            if offset > 0 {
                writeln!(writer)?;
                writeln!(writer, "{separator}")?;
                writeln!(writer)?;
            }
            let one_based = start_index + offset;
            let block = format_finding_block(finding, one_based, total, file_cache, source_cache);
            write!(writer, "{}", block.trim_end())?;
        }
        writeln!(writer)?;
        writer.flush()?;
        chunk_count += 1;
    }

    Ok(chunk_count)
}

pub(super) fn chunk_file_names(findings_len: usize, chunk_size: usize) -> Vec<String> {
    (0..findings_len)
        .step_by(chunk_size.max(1))
        .map(|start| {
            let start_index = start + 1;
            let end_index = (start + chunk_size.max(1)).min(findings_len);
            format!("Chunk_{start_index}_{end_index}.txt")
        })
        .collect()
}

pub(super) fn clean_matching_txt_files(
    output_dir: &Path,
    should_remove: impl Fn(&str) -> bool,
) -> Result<(), Error> {
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if should_remove(&name) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

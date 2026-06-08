//! Finding export helpers for context files and chunk files.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use crate::rules::Finding;

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

fn format_finding_block(
    finding: &Finding,
    index: usize,
    total: usize,
    file_cache: &mut HashMap<String, Option<String>>,
    source_cache: &HashMap<String, Arc<str>>,
) -> String {
    let mut lines = vec![
        format!("Finding {index}/{total}"),
        format!(
            "Source: {}:{}:{}",
            finding.file, finding.line, finding.column
        ),
        format!("Rule: {}", finding.rule_id),
        format!("Rule title: {}", finding.rule_title),
        format!("Severity: {}", finding.severity),
        format!("Message: {}", finding.message),
    ];

    if let Some(cwes) = finding.cwe.as_deref() {
        if !cwes.is_empty() {
            let list = cwes
                .iter()
                .map(|cwe| format!("CWE-{} ({})", cwe.id, cwe.name))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("CWEs: {list}"));
        }
    }

    if let Some(fix) = &finding.fix {
        if !fix.trim().is_empty() {
            lines.push(format!("Fix: {fix}"));
        }
    }

    if let (Some(start_line), Some(end_line)) =
        (finding.function_start_line, finding.function_end_line)
    {
        lines.push(format!("Enclosing function: lines {start_line}–{end_line}"));
    }

    lines.push("Context:".to_string());
    for line in finding_context_lines(finding, file_cache, source_cache) {
        lines.push(format!("    {line}"));
    }

    format!("{}\n", lines.join("\n"))
}

fn finding_context_lines(
    finding: &Finding,
    file_cache: &mut HashMap<String, Option<String>>,
    source_cache: &HashMap<String, Arc<str>>,
) -> Vec<String> {
    let mut get_content = || -> Option<String> {
        source_cache
            .get(&finding.file)
            .map(|s| s.to_string())
            .or_else(|| {
                file_cache
                    .entry(finding.file.clone())
                    .or_insert_with(|| fs::read_to_string(&finding.file).ok())
                    .clone()
            })
    };

    if let Some(snippet) = &finding.snippet {
        let snippet_lines = snippet
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if !snippet_lines.is_empty() {
            return snippet_lines;
        }
    }

    if let (Some(start_byte), Some(end_byte)) =
        (finding.function_start_byte, finding.function_end_byte)
    {
        let content = get_content();
        if let Some(content) = content {
            let end_byte = end_byte.min(content.len()).max(start_byte);
            let start_byte = start_byte.min(content.len());
            let body = &content[start_byte..end_byte];
            let first_line_no = finding.function_start_line.unwrap_or(1);
            let mut out = Vec::new();
            for (offset, line) in body.lines().enumerate() {
                let line_no = first_line_no + offset;
                let marker = if line_no == finding.line { ">" } else { " " };
                out.push(format!("{marker} {line_no:>5}: {line}"));
            }
            if !out.is_empty() {
                return out;
            }
        }
    }

    let content = get_content();

    if let Some(content) = content {
        let start = finding.line.saturating_sub(2).max(1);
        let end = finding.line + 1;
        let mut lines = Vec::new();
        for (index, line) in content.lines().enumerate() {
            let line_no = index + 1;
            if line_no < start {
                continue;
            }
            if line_no > end {
                break;
            }
            let marker = if line_no == finding.line { ">" } else { " " };
            lines.push(format!("{marker} {line_no:>5}: {line}"));
        }
        if !lines.is_empty() {
            return lines;
        }
    }

    vec!["<context unavailable>".to_string()]
}

fn write_chunk_files_streaming(
    findings: &[Finding],
    output_dir: &Path,
    chunk_size: usize,
    file_cache: &mut HashMap<String, Option<String>>,
    source_cache: &HashMap<String, Arc<str>>,
) -> Result<usize> {
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

fn clean_matching_txt_files(output_dir: &Path, keep_if: impl Fn(&str) -> bool) -> Result<()> {
    for entry in fs::read_dir(output_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if keep_if(&name) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

//! Finding export helpers for context files and chunk files.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone)]
struct FindingBlock {
    text: String,
}

pub fn export_findings(findings: &[Finding], options: &ExportOptions) -> Result<ExportSummary> {
    if !options.export_context && !options.export_chunks {
        return Ok(ExportSummary::default());
    }

    let mut source_cache = HashMap::<String, Option<String>>::new();
    let total = findings.len();
    let blocks = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| build_finding_block(finding, index + 1, total, &mut source_cache))
        .collect::<Vec<_>>();

    let mut summary = ExportSummary::default();
    if options.export_context {
        summary.context_files_written = write_context_files(&blocks, &options.context_output_dir)?;
    }
    if options.export_chunks {
        summary.chunk_files_written = write_chunk_files(
            &blocks,
            &options.chunks_output_dir,
            options.chunk_size.max(1),
        )?;
    }
    Ok(summary)
}

fn build_finding_block(
    finding: &Finding,
    index: usize,
    total: usize,
    source_cache: &mut HashMap<String, Option<String>>,
) -> FindingBlock {
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

    if !finding.cwe.is_empty() {
        let cwes = finding
            .cwe
            .iter()
            .map(|cwe| format!("CWE-{} ({})", cwe.id, cwe.name))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("CWEs: {cwes}"));
    }

    if let Some(fix) = &finding.fix {
        if !fix.trim().is_empty() {
            lines.push(format!("Fix: {fix}"));
        }
    }

    lines.push("Context:".to_string());
    for line in finding_context_lines(finding, source_cache) {
        lines.push(format!("    {line}"));
    }

    FindingBlock {
        text: format!("{}\n", lines.join("\n")),
    }
}

fn finding_context_lines(
    finding: &Finding,
    source_cache: &mut HashMap<String, Option<String>>,
) -> Vec<String> {
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

    let content = source_cache
        .entry(finding.file.clone())
        .or_insert_with(|| fs::read_to_string(&finding.file).ok());

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

fn write_context_files(blocks: &[FindingBlock], output_dir: &Path) -> Result<usize> {
    fs::create_dir_all(output_dir)?;
    clean_matching_txt_files(output_dir, |name| name.ends_with(".txt"))?;

    for (index, block) in blocks.iter().enumerate() {
        let output_path = output_dir.join(format!("{}.txt", index + 1));
        fs::write(output_path, &block.text)?;
    }
    Ok(blocks.len())
}

fn write_chunk_files(
    blocks: &[FindingBlock],
    output_dir: &Path,
    chunk_size: usize,
) -> Result<usize> {
    fs::create_dir_all(output_dir)?;
    clean_matching_txt_files(output_dir, |name| {
        name.starts_with("Chunk_") && name.ends_with(".txt")
    })?;

    let separator = "=".repeat(100);
    let total = blocks.len();

    for (chunk_index, chunk) in blocks.chunks(chunk_size).enumerate() {
        let start_index = chunk_index * chunk_size + 1;
        let end_index = start_index + chunk.len().saturating_sub(1);
        let output_path = output_dir.join(format!("Chunk_{start_index}_{end_index}.txt"));
        fs::write(
            output_path,
            build_chunk_content(chunk, start_index, end_index, total, &separator),
        )?;
    }

    Ok(blocks.chunks(chunk_size).count())
}

fn build_chunk_content(
    blocks: &[FindingBlock],
    start_index: usize,
    end_index: usize,
    total: usize,
    separator: &str,
) -> String {
    let mut parts = vec![
        format!("Findings {start_index}-{end_index} of {total}"),
        String::new(),
    ];

    for (offset, block) in blocks.iter().enumerate() {
        if offset > 0 {
            parts.push(separator.to_string());
            parts.push(String::new());
        }
        parts.push(block.text.trim_end().to_string());
    }

    format!("{}\n", parts.join("\n"))
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{ExportOptions, export_findings};
    use crate::cwe::CweRef;
    use crate::rules::{Finding, LineCol, Severity};

    #[test]
    fn exports_context_and_chunk_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("slopguard-export-test-{unique}"));
        let source_path = root.join("sample.go");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            &source_path,
            "package main\n\nfunc main() {\n    s += x\n}\n",
        )
        .unwrap();

        let findings = vec![Finding::new(
            "CWE-89",
            "SQL injection via concatenated query",
            source_path.to_string_lossy().to_string(),
            LineCol { line: 4, column: 5 },
            "query string is built from untrusted input",
            Severity::Warning,
            vec![CweRef::new(
                89,
                "Improper Neutralization of Special Elements used in an SQL Command",
                "https://cwe.mitre.org/data/definitions/89.html",
            )],
        )];

        let summary = export_findings(
            &findings,
            &ExportOptions {
                export_context: true,
                export_chunks: true,
                chunk_size: 25,
                context_output_dir: root.join("findings/functions"),
                chunks_output_dir: root.join("chunks"),
            },
        )
        .unwrap();

        assert_eq!(summary.context_files_written, 1);
        assert_eq!(summary.chunk_files_written, 1);
        assert!(root.join("findings/functions/1.txt").exists());
        assert!(root.join("chunks/Chunk_1_1.txt").exists());

        std::fs::remove_dir_all(root).unwrap();
    }
}

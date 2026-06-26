//! `finding_context_lines`: retrieve the source context for a finding
//! using either the in-memory snippet, the enclosing function range, or
//! a default "few lines before/after" window.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use crate::rules::Finding;

pub(super) fn finding_context_lines(
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

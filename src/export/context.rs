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
        let content = source_cache
            .get(&finding.file)
            .map(AsRef::as_ref)
            .or_else(|| {
                file_cache
                    .entry(finding.file.clone())
                    .or_insert_with(|| fs::read_to_string(&finding.file).ok())
                    .as_deref()
            });
        if let Some(content) = content {
            let start_byte = start_byte.min(content.len());
            let end_byte = end_byte.min(content.len()).max(start_byte);
            // Byte spans originate in tree-sitter, but a stale or external
            // finding can bisect UTF-8. `get` makes export fall back to line
            // context instead of panicking on an invalid boundary.
            let Some(body) = content.get(start_byte..end_byte) else {
                return line_window(finding, content);
            };
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

    let content = source_cache
        .get(&finding.file)
        .map(AsRef::as_ref)
        .or_else(|| {
            file_cache
                .entry(finding.file.clone())
                .or_insert_with(|| fs::read_to_string(&finding.file).ok())
                .as_deref()
        });
    if let Some(content) = content {
        return line_window(finding, content);
    }

    vec!["<context unavailable>".to_string()]
}

fn line_window(finding: &Finding, content: &str) -> Vec<String> {
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
    if lines.is_empty() {
        vec!["<context unavailable>".to_string()]
    } else {
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{FindingInputs, LineCol, Severity};
    use std::borrow::Cow;

    fn finding_with_range(file: &str, line: usize, start: usize, end: usize) -> Finding {
        Finding::new(FindingInputs::new(
            "CWE-89",
            "title",
            file,
            LineCol { line, column: 1 },
            "message",
            Severity::Medium,
            Cow::Borrowed(&[]),
        ))
        .with_function_range(start, end, 1, line)
    }

    #[test]
    fn malformed_byte_range_falls_back_to_line_window() {
        let file = "sample.go";
        // Rocket is 4 bytes starting at offset 1; slicing [2..3] bisects UTF-8.
        let unicode: Arc<str> = Arc::from("a🚀b\n");
        let mut cache = HashMap::new();
        cache.insert(file.to_string(), Arc::clone(&unicode));
        let finding = finding_with_range(file, 1, 2, 3);
        let lines = finding_context_lines(&finding, &mut HashMap::new(), &cache);
        assert!(
            lines
                .iter()
                .any(|line| line.contains('🚀') || line.contains('a')),
            "expected line-window fallback, got {lines:?}"
        );
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn unicode_aligned_range_renders_function_body() {
        let file = "sample.go";
        let source: Arc<str> = Arc::from("func 日本語() {\n  return\n}\n");
        let mut cache = HashMap::new();
        cache.insert(file.to_string(), Arc::clone(&source));
        let end = source.len();
        let finding = finding_with_range(file, 2, 0, end);
        let lines = finding_context_lines(&finding, &mut HashMap::new(), &cache);
        assert!(
            lines.iter().any(|line| line.contains("日本語")),
            "got {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.starts_with('>')),
            "got {lines:?}"
        );
    }

    #[test]
    fn borrows_cached_arc_str_without_requiring_file_cache() {
        let file = "sample.go";
        let source: Arc<str> = Arc::from("line1\nline2\nline3\n");
        let mut cache = HashMap::new();
        cache.insert(file.to_string(), source);
        let finding = finding_with_range(file, 2, 0, 5);
        let lines = finding_context_lines(&finding, &mut HashMap::new(), &cache);
        assert!(!lines.is_empty());
        assert!(lines.iter().any(|line| line.contains("line1")));
    }
}

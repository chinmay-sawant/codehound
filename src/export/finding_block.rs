//! `format_finding_block`: format a single finding as a text block.

use std::collections::HashMap;
use std::sync::Arc;

use crate::cwe::format_cwe_list;
use crate::rules::Finding;

use super::context::finding_context_lines;

pub(super) fn format_finding_block(
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
        format!("Fingerprint: {}", finding.fingerprint_string()),
        format!("Rule title: {}", finding.rule_title),
        format!("Severity: {}", finding.severity),
        format!("Message: {}", finding.message),
    ];

    if let Some(cwes) = finding.cwe.as_deref().filter(|cwes| !cwes.is_empty()) {
        lines.push(format!("CWEs: {}", format_cwe_list(cwes)));
    }

    if let Some(fix) = &finding.fix {
        if !fix.trim().is_empty() {
            lines.push(format!("Fix: {fix}"));
        }
    }
    if let Some(evidence) = &finding.evidence {
        let evidence = serde_json::to_string(evidence)
            .unwrap_or_else(|err| format!("{{\"serialization_error\":\"{err}\"}}"));
        lines.push(format!("Evidence: {evidence}"));
    }
    if let Some(confidence) = finding.confidence {
        lines.push(format!("Confidence: {confidence}"));
    }
    if let Some(tags) = finding.tags.as_deref().filter(|tags| !tags.is_empty()) {
        lines.push(format!("Tags: {}", tags.join(", ")));
    }
    if let Some(remediation) = finding
        .remediation
        .as_deref()
        .filter(|remediation| !remediation.trim().is_empty())
    {
        lines.push(format!("Remediation: {remediation}"));
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

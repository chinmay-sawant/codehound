//! A single finding emitted by a detector.

use serde::Serialize;

use super::Severity;
use crate::cwe::CweRef;

/// A single static-analysis finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Rule id, e.g. `SLOP001`.
    pub rule_id: &'static str,
    /// Rule title.
    pub rule_title: &'static str,
    /// File path (relative to the analyzed root when possible).
    pub file: String,
    /// 1-indexed line.
    pub line: usize,
    /// 1-indexed column.
    pub column: usize,
    /// Source snippet, if available.
    pub snippet: Option<String>,
    /// Free-form message.
    pub message: String,
    /// Severity.
    pub severity: Severity,
    /// Linked CWEs.
    pub cwe: Vec<CweRef>,
    /// Optional suggestion.
    pub fix: Option<String>,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        rule_title: &'static str,
        file: impl Into<String>,
        line: usize,
        column: usize,
        message: impl Into<String>,
        severity: Severity,
        cwe: Vec<CweRef>,
    ) -> Self {
        Self {
            rule_id,
            rule_title,
            file: file.into(),
            line,
            column,
            snippet: None,
            message: message.into(),
            severity,
            cwe,
            fix: None,
        }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

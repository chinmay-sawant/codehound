//! A single finding emitted by a detector.

use std::borrow::Cow;

use serde::{Serialize, Serializer};

use super::Severity;
use super::fingerprint::Fingerprint;
use crate::cwe::CweRef;

/// 1-indexed line and column in a source file.
#[derive(Debug, Clone, Copy)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

/// Serialize `Option<Box<[T]>>` so that `None` and `Some(&[])` both emit as
/// `[]` (preserves the historical wire shape for JSON consumers).
fn serialize_optional_cwe<S: Serializer>(
    cwe: &Option<Box<[CweRef]>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match cwe {
        Some(slice) => slice.serialize(serializer),
        None => Vec::<CweRef>::new().serialize(serializer),
    }
}

/// A single static-analysis finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Rule id, e.g. `CWE-89`.
    pub rule_id: &'static str,
    /// Rule title.
    pub rule_title: &'static str,
    /// File path (relative to the analyzed root when possible).
    pub file: String,
    /// 1-indexed line.
    pub line: usize,
    /// 1-indexed column.
    pub column: usize,
    /// 1-indexed end line of the matched region, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    /// 1-indexed end column of the matched region, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    /// 0-indexed byte offset of the match start within the source file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<usize>,
    /// Number of bytes covered by the match, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
    /// 0-indexed byte offset of the start of the enclosing function, when
    /// resolved by the analyzer's function-context pass. Pairs with
    /// [`Finding::function_end_byte`] to give the full function body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_start_byte: Option<usize>,
    /// Past-the-end byte offset of the enclosing function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_end_byte: Option<usize>,
    /// 1-indexed start line of the enclosing function, for display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_start_line: Option<usize>,
    /// 1-indexed end line of the enclosing function, for display only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_end_line: Option<usize>,
    /// Source snippet, if available.
    pub snippet: Option<String>,
    /// Free-form message.
    pub message: String,
    /// Severity.
    pub severity: Severity,
    /// Linked CWEs. `None` and `Some(&[])` both mean "no CWEs"; the
    /// `#[serde]` attribute ensures JSON output is always `[]` for either.
    #[serde(serialize_with = "serialize_optional_cwe")]
    pub cwe: Option<Box<[CweRef]>>,
    /// Optional suggestion.
    pub fix: Option<String>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: &'static str,
        rule_title: &'static str,
        file: impl Into<String>,
        location: LineCol,
        message: impl Into<String>,
        severity: Severity,
        cwe: Cow<'static, [CweRef]>,
    ) -> Self {
        let cwe = if cwe.is_empty() {
            None
        } else {
            Some(cwe.into_owned().into_boxed_slice())
        };
        Self {
            rule_id,
            rule_title,
            file: file.into(),
            line: location.line,
            column: location.column,
            end_line: None,
            end_column: None,
            byte_offset: None,
            byte_length: None,
            function_start_byte: None,
            function_end_byte: None,
            function_start_line: None,
            function_end_line: None,
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

    /// Attach byte-range information to the finding.
    pub fn with_byte_range(mut self, byte_offset: usize, byte_length: usize) -> Self {
        self.byte_offset = Some(byte_offset);
        self.byte_length = Some(byte_length);
        self
    }

    /// Attach end-line/end-column information to the finding.
    pub fn with_end(mut self, end_line: usize, end_column: usize) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }

    /// Attach the enclosing function's byte/line range. The exporter uses
    /// the byte range to render the whole function body for this finding
    /// instead of the default "few lines before/after" window.
    pub fn with_function_range(
        mut self,
        start_byte: usize,
        end_byte: usize,
        start_line: usize,
        end_line: usize,
    ) -> Self {
        self.function_start_byte = Some(start_byte);
        self.function_end_byte = Some(end_byte);
        self.function_start_line = Some(start_line);
        self.function_end_line = Some(end_line);
        self
    }

    /// Compute a stable cross-run fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_finding(self)
    }

    /// Convenience string form for wire output.
    pub fn fingerprint_string(&self) -> String {
        self.fingerprint().to_string()
    }
}

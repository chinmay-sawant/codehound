//! A single finding emitted by a detector.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use std::borrow::Cow;

use serde::{Serialize, Serializer};

use super::Severity;
use super::evidence::DetectorEvidence;
use super::fingerprint::Fingerprint;
use crate::cwe::CweRef;

/// 1-indexed line and column in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

/// Serialize `Option<Box<[T]>>` so that `None` and `Some(&[])` both emit as
/// `[]` (preserves the historical wire shape for JSON consumers).
// ponytail: serde lacks native "None → []" serialization. Custom fn is the shortest path.
fn serialize_optional_cwe<S: Serializer>(
    cwe: &Option<Box<[CweRef]>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match cwe {
        Some(slice) => slice.serialize(serializer),
        None => Vec::<CweRef>::new().serialize(serializer),
    }
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

/// Core fields required to construct a [`Finding`].
#[derive(Debug, Clone)]
pub struct FindingInputs {
    /// Rule id, e.g. `CWE-89`.
    pub rule_id: &'static str,
    /// Rule title.
    pub rule_title: &'static str,
    /// File path (relative to the analyzed root when possible).
    pub file: String,
    /// 1-indexed line and column of the match.
    pub location: LineCol,
    /// Free-form message.
    pub message: String,
    /// Severity.
    pub severity: Severity,
    /// Linked CWEs. An empty slice means no CWEs.
    pub cwe: Cow<'static, [CweRef]>,
}

impl FindingInputs {
    /// Convenience constructor for detectors, tests, and fixtures.
    pub fn new(
        rule_id: &'static str,
        rule_title: &'static str,
        file: impl Into<String>,
        location: LineCol,
        message: impl Into<String>,
        severity: Severity,
        cwe: Cow<'static, [CweRef]>,
    ) -> Self {
        Self {
            rule_id,
            rule_title,
            file: file.into(),
            location,
            message: message.into(),
            severity,
            cwe,
        }
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
    // ponytail: end_line/end_column/byte_offset/byte_length are always None in
    // new findings but kept for the JSON/SARIF/finding_wire API shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<usize>,
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
    /// Machine-readable structured evidence for downstream processing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<DetectorEvidence>,
    /// Confidence score from 0.0 to 1.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Tags for filtering or grouping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Whether the finding is suppressed but still included in output.
    #[serde(skip_serializing_if = "is_false")]
    pub suppressed: bool,
    /// Human-readable remediation guidance beyond the short fix suggestion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    /// Construct a finding from [`FindingInputs`]; chain `with_*` methods for optional fields.
    pub fn new(inputs: FindingInputs) -> Self {
        let cwe = if inputs.cwe.is_empty() {
            None
        } else {
            Some(inputs.cwe.into_owned().into_boxed_slice())
        };
        Self {
            rule_id: inputs.rule_id,
            rule_title: inputs.rule_title,
            file: inputs.file,
            line: inputs.location.line,
            column: inputs.location.column,
            end_line: None,
            end_column: None,
            byte_offset: None,
            byte_length: None,
            function_start_byte: None,
            function_end_byte: None,
            function_start_line: None,
            function_end_line: None,
            snippet: None,
            message: inputs.message,
            severity: inputs.severity,
            cwe,
            fix: None,
            evidence: None,
            confidence: None,
            tags: None,
            suppressed: false,
            remediation: None,
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

    pub fn with_evidence(mut self, evidence: DetectorEvidence) -> Self {
        self.evidence = Some(evidence);
        self
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence);
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn mark_suppressed(mut self) -> Self {
        self.suppressed = true;
        self
    }

    // ponytail: with_byte_range/with_end kept for API shape (reporting reads the fields).
    pub fn with_byte_range(mut self, byte_offset: usize, byte_length: usize) -> Self {
        self.byte_offset = Some(byte_offset);
        self.byte_length = Some(byte_length);
        self
    }

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

    /// Convenience string form for wire output.
    pub fn fingerprint_string(&self) -> String {
        Fingerprint::from_finding(self).to_string()
    }
}

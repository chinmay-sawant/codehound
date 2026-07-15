//! A single finding emitted by a detector.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use std::borrow::Cow;

use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};

use super::Severity;
use super::evidence::DetectorEvidence;
use super::finding_wire::FindingWire;
use crate::cwe::CweRef;

pub(crate) const FINGERPRINT_TOOL: &str = "codehound";
/// v2: rule + file + message digest (line-shift resilient when message is stable).
pub(crate) const FINGERPRINT_VERSION: u32 = 2;

fn format_fingerprint(rule_id: &str, file: &str, message: &str) -> String {
    use sha2::{Digest, Sha256};
    // sha2 0.11 digest arrays no longer implement LowerHex; hex via shared helper.
    let msg_hash = crate::engine::hex_lower(Sha256::digest(message.as_bytes()));
    format!(
        "{}:{}:{}:{}:{}",
        FINGERPRINT_TOOL,
        FINGERPRINT_VERSION,
        rule_id,
        file.replace('\\', "/"),
        &msg_hash[..16.min(msg_hash.len())],
    )
}

/// 1-indexed line and column in a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

impl LineCol {
    /// Construct a location while enforcing the public 1-indexed invariant.
    pub const fn try_new(line: usize, column: usize) -> Option<Self> {
        if line == 0 || column == 0 {
            None
        } else {
            Some(Self { line, column })
        }
    }
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

fn is_false(value: &bool) -> bool {
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

    /// Set confidence after validating that it is finite and within `0..=1`.
    pub fn with_confidence_checked(self, confidence: f32) -> Result<Self, &'static str> {
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err("confidence must be finite and within 0..=1");
        }
        Ok(self.with_confidence(confidence))
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

    /// Set a byte range after checking that its end does not overflow.
    pub fn with_byte_range_checked(
        self,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<Self, &'static str> {
        byte_offset
            .checked_add(byte_length)
            .ok_or("byte range exceeds usize")?;
        Ok(self.with_byte_range(byte_offset, byte_length))
    }

    pub fn with_end(mut self, end_line: usize, end_column: usize) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }

    /// Set an end location after enforcing the 1-indexed invariant.
    pub fn with_end_checked(
        self,
        end_line: usize,
        end_column: usize,
    ) -> Result<Self, &'static str> {
        if end_line == 0
            || end_column == 0
            || end_line < self.line
            || (end_line == self.line && end_column < self.column)
        {
            return Err("finding end location must be 1-indexed");
        }
        Ok(self.with_end(end_line, end_column))
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

    /// Set an enclosing function range after validating ordering and lines.
    pub fn with_function_range_checked(
        self,
        start_byte: usize,
        end_byte: usize,
        start_line: usize,
        end_line: usize,
    ) -> Result<Self, &'static str> {
        if start_byte > end_byte || start_line == 0 || end_line < start_line {
            return Err("function range is invalid");
        }
        Ok(self.with_function_range(start_byte, end_byte, start_line, end_line))
    }

    /// Content-stable fingerprint (rule + file + message digest).
    /// Prefer this over line/column for baseline identity.
    pub fn fingerprint_string(&self) -> String {
        format_fingerprint(self.rule_id, &self.file, &self.message)
    }

    /// Rule category derived from the rule id prefix.
    pub fn category(&self) -> &'static str {
        super::category_for_rule_id(self.rule_id)
    }
}

impl<'de> Deserialize<'de> for Finding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        FindingWire::deserialize(deserializer)?
            .into_finding()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_wire_round_trips_via_finding_wire() {
        let f = Finding::new(FindingInputs::new(
            "CWE-1",
            "t",
            "a.go",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Low,
            std::borrow::Cow::Borrowed(&[]),
        ));
        let wire = FindingWire::from(f.clone());
        assert_eq!(wire.rule_id, "CWE-1");
        assert_eq!(wire.into_finding().unwrap().rule_id, f.rule_id);
    }
}

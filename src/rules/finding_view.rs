//! Shared read-only view over [`Finding`] for reporters and wire adapters.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use crate::cwe::CweRef;

use super::Finding;
use super::evidence::DetectorEvidence;
use super::severity::Severity;

/// Borrowed view that centralizes optional-field and derived accessors so
/// JSON, text, export, SARIF, and cache wire adapters share one field layer.
pub struct FindingView<'a> {
    inner: &'a Finding,
}

impl<'a> FindingView<'a> {
    /// Wrap a finding for shared reporter / wire access.
    pub fn new(f: &'a Finding) -> Self {
        Self { inner: f }
    }

    /// Underlying finding reference.
    pub fn inner(&self) -> &'a Finding {
        self.inner
    }

    pub fn rule_id(&self) -> &'static str {
        self.inner.rule_id
    }

    pub fn rule_title(&self) -> &'static str {
        self.inner.rule_title
    }

    pub fn severity(&self) -> Severity {
        self.inner.severity
    }

    pub fn message(&self) -> &'a str {
        self.inner.message.as_str()
    }

    pub fn file(&self) -> &'a str {
        self.inner.file.as_str()
    }

    pub fn line(&self) -> usize {
        self.inner.line
    }

    pub fn column(&self) -> usize {
        self.inner.column
    }

    pub fn end_line(&self) -> Option<usize> {
        self.inner.end_line
    }

    pub fn end_column(&self) -> Option<usize> {
        self.inner.end_column
    }

    pub fn byte_offset(&self) -> Option<usize> {
        self.inner.byte_offset
    }

    pub fn byte_length(&self) -> Option<usize> {
        self.inner.byte_length
    }

    pub fn snippet(&self) -> Option<&'a str> {
        self.inner.snippet.as_deref()
    }

    pub fn suppressed(&self) -> bool {
        self.inner.suppressed
    }

    pub fn evidence(&self) -> Option<&'a DetectorEvidence> {
        self.inner.evidence.as_ref()
    }

    pub fn confidence(&self) -> Option<f32> {
        self.inner.confidence
    }

    /// Rule category derived from the rule id prefix.
    pub fn category(&self) -> &'static str {
        self.inner.category()
    }

    /// Deterministic fingerprint for wire output.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint_string()
    }

    /// Linked CWEs when the slice is non-empty.
    pub fn non_empty_cwe(&self) -> Option<&'a [CweRef]> {
        self.inner.cwe.as_deref().filter(|c| !c.is_empty())
    }

    /// Fix text when present and non-blank.
    pub fn non_empty_fix(&self) -> Option<&'a str> {
        self.inner.fix.as_deref().filter(|s| !s.trim().is_empty())
    }

    /// Tags when present and non-empty.
    pub fn non_empty_tags(&self) -> Option<&'a [String]> {
        self.inner.tags.as_deref().filter(|t| !t.is_empty())
    }

    /// Remediation text when present and non-blank.
    pub fn non_empty_remediation(&self) -> Option<&'a str> {
        self.inner
            .remediation
            .as_deref()
            .filter(|s| !s.trim().is_empty())
    }

    /// Enclosing function line range when both bounds are set.
    pub fn function_line_range(&self) -> Option<(usize, usize)> {
        match (self.inner.function_start_line, self.inner.function_end_line) {
            (Some(start), Some(end)) => Some((start, end)),
            _ => None,
        }
    }

    /// Confidence when set and below certainty (1.0).
    pub fn partial_confidence(&self) -> Option<f32> {
        self.inner.confidence.filter(|c| *c < 1.0)
    }

    /// SARIF tag set derived from category, CWEs, and extra tags.
    pub fn sarif_tags(&self) -> Vec<String> {
        let mut tags = vec!["security".to_string()];
        if let Some(family) = super::sarif_family_tag_for_rule_id(self.rule_id()) {
            tags.push(family.to_string());
        }
        if let Some(cwes) = self.non_empty_cwe() {
            for c in cwes {
                let tag = format!("cwe-{}", c.id);
                if !tags.iter().any(|t| t == &tag) {
                    tags.push(tag);
                }
            }
        }
        if let Some(extra) = self.non_empty_tags() {
            for tag in extra {
                if !tags.iter().any(|t| t == tag) {
                    tags.push(tag.clone());
                }
            }
        }
        tags
    }

    /// Optional taint-path flag from structured evidence.
    pub fn taint_show_paths(&self) -> Option<bool> {
        self.evidence()
            .and_then(DetectorEvidence::taint_show_paths_flag)
    }
}

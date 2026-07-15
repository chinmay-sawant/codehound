//! Shared read-only view over [`Finding`] for reporters and wire adapters.
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

    /// Return the stable rule identifier.
    pub fn rule_id(&self) -> &'static str {
        self.inner.rule_id
    }

    /// Return the human-readable rule title.
    pub fn rule_title(&self) -> &'static str {
        self.inner.rule_title
    }

    /// Return the finding severity.
    pub fn severity(&self) -> Severity {
        self.inner.severity
    }

    /// Return the finding message.
    pub fn message(&self) -> &'a str {
        self.inner.message.as_str()
    }

    /// Return the finding file path.
    pub fn file(&self) -> &'a str {
        self.inner.file.as_str()
    }

    /// Return the one-indexed start line.
    pub fn line(&self) -> usize {
        self.inner.line
    }

    /// Return the one-indexed start column.
    pub fn column(&self) -> usize {
        self.inner.column
    }

    /// Return the optional one-indexed end line.
    pub fn end_line(&self) -> Option<usize> {
        self.inner.end_line
    }

    /// Return the optional one-indexed end column.
    pub fn end_column(&self) -> Option<usize> {
        self.inner.end_column
    }

    /// Return the optional byte offset.
    pub fn byte_offset(&self) -> Option<usize> {
        self.inner.byte_offset
    }

    /// Return the optional byte length.
    pub fn byte_length(&self) -> Option<usize> {
        self.inner.byte_length
    }

    /// Return the optional source snippet.
    pub fn snippet(&self) -> Option<&'a str> {
        self.inner.snippet.as_deref()
    }

    /// Return whether the finding is suppressed.
    pub fn suppressed(&self) -> bool {
        self.inner.suppressed
    }

    /// Return structured detector evidence when present.
    pub fn evidence(&self) -> Option<&'a DetectorEvidence> {
        self.inner.evidence.as_ref()
    }

    /// Return the optional confidence score.
    pub fn confidence(&self) -> Option<f32> {
        self.inner.confidence
    }

    /// Return the derived rule category.
    pub fn category(&self) -> &'static str {
        self.inner.category()
    }

    /// Return the deterministic finding fingerprint.
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint_string()
    }

    /// Return linked CWEs when the list is non-empty.
    pub fn non_empty_cwe(&self) -> Option<&'a [CweRef]> {
        self.inner.cwe.as_deref().filter(|c| !c.is_empty())
    }

    /// Return non-blank fix text when present.
    pub fn non_empty_fix(&self) -> Option<&'a str> {
        self.inner.fix.as_deref().filter(|s| !s.trim().is_empty())
    }

    /// Return non-empty tags when present.
    pub fn non_empty_tags(&self) -> Option<&'a [String]> {
        self.inner.tags.as_deref().filter(|t| !t.is_empty())
    }

    /// Return non-blank remediation text when present.
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

    /// Return confidence values below certainty.
    pub fn partial_confidence(&self) -> Option<f32> {
        self.inner.confidence.filter(|c| *c < 1.0)
    }

    /// Build SARIF tags from category, CWEs, and explicit tags.
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

    /// Return whether taint hop details were included.
    pub fn taint_show_paths(&self) -> Option<bool> {
        self.evidence()
            .and_then(DetectorEvidence::taint_show_paths_flag)
    }
}

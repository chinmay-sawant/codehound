//! Wire shape used by the cache when serializing a finding. Mirrors
//! [`Finding`] except `cwe` is owned and `rule_id` / `rule_title` are
//! `String`s. The cache writes this struct and converts back to
//! [`Finding`] on read.
//!
//! ponytail: Needed because CweRef has &'static str fields (can't Deserialize).
//! The leak-to-static pattern is acceptable — bounded working set per cache load.

use serde::{Deserialize, Serialize};

use crate::cwe::CweRef;

use super::finding::Finding;

/// Owned CWE reference used during deserialization. [`CweRef`] holds
/// `&'static str` so it cannot be `Deserialize` directly; this mirror
/// owns its strings and is converted back into `CweRef` when the cache
/// loads a finding.
///
/// Only the fields the cache actually needs are preserved. We leak the
/// strings into `'static` storage so the resulting `CweRef` is valid for
/// the rest of the process. This is acceptable for the cache use case
/// because the working set is bounded by the number of unique CWE IDs
/// across all cache entries — typically a few hundred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OwnedCweRef {
    id: u32,
    name: String,
    url: String,
}

impl OwnedCweRef {
    fn into_static(self) -> CweRef {
        CweRef {
            id: self.id,
            name: Box::leak(self.name.into_boxed_str()),
            url: Box::leak(self.url.into_boxed_str()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FindingWire {
    pub rule_id: String,
    pub rule_title: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub byte_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub byte_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_start_byte: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_end_byte: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_start_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub function_end_line: Option<usize>,
    pub snippet: Option<String>,
    pub message: String,
    pub severity: super::Severity,
    #[serde(default)]
    pub cwe: Vec<OwnedCweRef>,
    pub fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub evidence: Option<super::evidence::DetectorEvidence>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remediation: Option<String>,
}

impl From<Finding> for FindingWire {
    fn from(f: Finding) -> Self {
        let cwe = f
            .cwe
            .map(|c| {
                c.iter()
                    .map(|c| OwnedCweRef {
                        id: c.id,
                        name: c.name.to_string(),
                        url: c.url.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            rule_id: f.rule_id.to_string(),
            rule_title: f.rule_title.to_string(),
            file: f.file,
            line: f.line,
            column: f.column,
            end_line: f.end_line,
            end_column: f.end_column,
            byte_offset: f.byte_offset,
            byte_length: f.byte_length,
            function_start_byte: f.function_start_byte,
            function_end_byte: f.function_end_byte,
            function_start_line: f.function_start_line,
            function_end_line: f.function_end_line,
            snippet: f.snippet,
            message: f.message,
            severity: f.severity,
            cwe,
            fix: f.fix,
            evidence: f.evidence,
            confidence: f.confidence,
            tags: f.tags,
            suppressed: f.suppressed,
            remediation: f.remediation,
        }
    }
}

impl FindingWire {
    /// Convert back to [`Finding`], leaking the CWE strings into
    /// `'static` storage. See [`OwnedCweRef`] for why this is acceptable
    /// for the cache use case.
    pub fn into_finding(self) -> Finding {
        let FindingWire {
            rule_id,
            rule_title,
            file,
            line,
            column,
            end_line,
            end_column,
            byte_offset,
            byte_length,
            function_start_byte,
            function_end_byte,
            function_start_line,
            function_end_line,
            snippet,
            message,
            severity,
            cwe,
            fix,
            evidence,
            confidence,
            tags,
            suppressed,
            remediation,
        } = self;
        let rule_id_static = Box::leak(rule_id.into_boxed_str());
        let rule_title_static = Box::leak(rule_title.into_boxed_str());
        let cwe = if cwe.is_empty() {
            None
        } else {
            let owned: Vec<CweRef> = cwe.into_iter().map(OwnedCweRef::into_static).collect();
            Some(owned.into_boxed_slice())
        };
        Finding {
            rule_id: rule_id_static,
            rule_title: rule_title_static,
            file,
            line,
            column,
            end_line,
            end_column,
            byte_offset,
            byte_length,
            function_start_byte,
            function_end_byte,
            function_start_line,
            function_end_line,
            snippet,
            message,
            severity,
            cwe,
            fix,
            evidence,
            confidence,
            tags,
            suppressed,
            remediation,
        }
    }
}

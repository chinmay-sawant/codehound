//! Wire shape used by the cache when serializing a finding. Mirrors
//! [`Finding`] except `cwe` is owned and `rule_id` / `rule_title` are
//! `String`s. The cache writes this struct and converts back to
//! [`Finding`] on read.
//!
//! Strings are interned for the small, stable rule metadata vocabulary. A
//! hard cap turns pathological cache input into a cache miss instead of an
//! unbounded process-lifetime allocation.

use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::cwe::CweRef;

use super::finding::{Finding, FindingInputs, LineCol};
use super::finding_view::FindingView;

const MAX_INTERNED_STRINGS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindingWireError {
    InvalidLocation,
    IncompleteEndLocation,
    InvalidEndLocation,
    IncompleteByteRange,
    ByteRangeOverflow,
    IncompleteFunctionRange,
    InvalidFunctionRange,
    InvalidConfidence,
    InterningLimit,
}

impl std::fmt::Display for FindingWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLocation => "finding location is invalid",
            Self::IncompleteEndLocation => "finding end location is incomplete",
            Self::InvalidEndLocation => "finding end location is invalid",
            Self::IncompleteByteRange => "finding byte range is incomplete",
            Self::ByteRangeOverflow => "finding byte range exceeds usize",
            Self::IncompleteFunctionRange => "finding function range is incomplete",
            Self::InvalidFunctionRange => "finding function range is invalid",
            Self::InvalidConfidence => "finding confidence is invalid",
            Self::InterningLimit => "cache string interning limit reached",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FindingWireError {}

/// Intern a string into process-lifetime storage, reusing prior entries.
/// Returns `None` when untrusted cache data exceeds the process cap.
fn intern_str(s: String) -> Option<&'static str> {
    use std::collections::HashSet;
    static TABLE: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let table = TABLE.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match table.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(&existing) = guard.get(s.as_str()) {
        return Some(existing);
    }
    if guard.len() >= MAX_INTERNED_STRINGS {
        return None;
    }
    let leaked: &'static str = Box::leak(s.into_boxed_str());
    guard.insert(leaked);
    Some(leaked)
}

/// Owned CWE reference used during deserialization. [`CweRef`] holds
/// `&'static str` so it cannot be `Deserialize` directly; this mirror
/// owns its strings and is converted back into `CweRef` when the cache
/// loads a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OwnedCweRef {
    id: u32,
    name: String,
    url: String,
}

impl OwnedCweRef {
    fn into_static(self) -> Option<CweRef> {
        Some(CweRef {
            id: self.id,
            name: intern_str(self.name)?,
            url: intern_str(self.url)?,
        })
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
        Self::from_finding(f)
    }
}

impl FindingWire {
    pub(crate) fn from_finding(f: Finding) -> Self {
        let view = FindingView::new(&f);
        let rule_id = view.rule_id().to_string();
        let rule_title = view.rule_title().to_string();
        let line = view.line();
        let column = view.column();
        let end_line = view.end_line();
        let end_column = view.end_column();
        let byte_offset = view.byte_offset();
        let byte_length = view.byte_length();
        let severity = view.severity();
        let confidence = view.confidence();
        let suppressed = view.suppressed();
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
            rule_id,
            rule_title,
            file: f.file,
            line,
            column,
            end_line,
            end_column,
            byte_offset,
            byte_length,
            function_start_byte: f.function_start_byte,
            function_end_byte: f.function_end_byte,
            function_start_line: f.function_start_line,
            function_end_line: f.function_end_line,
            snippet: f.snippet,
            message: f.message,
            severity,
            cwe,
            fix: f.fix,
            evidence: f.evidence,
            confidence,
            tags: f.tags,
            suppressed,
            remediation: f.remediation,
        }
    }
}

impl FindingWire {
    /// Convert back to [`Finding`], interning rule id/title and CWE strings.
    ///
    /// Returns an error when a corrupted or adversarial cache entry exceeds
    /// the process string-interning cap.
    ///
    /// # Errors
    ///
    /// Returns [`FindingWireError`] when locations, ranges, confidence, or
    /// bounded string interning data are malformed.
    pub fn into_finding(self) -> Result<Finding, FindingWireError> {
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

        // Validate untrusted positional fields before interning any strings.
        // Cache input must not be able to bypass Finding's checked builders.
        let location = LineCol::try_new(line, column).ok_or(FindingWireError::InvalidLocation)?;
        let end = match (end_line, end_column) {
            (None, None) => None,
            (Some(line), Some(column)) => Some((line, column)),
            _ => return Err(FindingWireError::IncompleteEndLocation),
        };
        let byte_range = match (byte_offset, byte_length) {
            (None, None) => None,
            (Some(offset), Some(length)) => Some((offset, length)),
            _ => return Err(FindingWireError::IncompleteByteRange),
        };
        if let Some((offset, length)) = byte_range {
            offset
                .checked_add(length)
                .ok_or(FindingWireError::ByteRangeOverflow)?;
        }
        let function_range = match (
            function_start_byte,
            function_end_byte,
            function_start_line,
            function_end_line,
        ) {
            (None, None, None, None) => None,
            (Some(start_byte), Some(end_byte), Some(start_line), Some(end_line)) => {
                Some((start_byte, end_byte, start_line, end_line))
            }
            _ => return Err(FindingWireError::IncompleteFunctionRange),
        };
        if let Some(confidence) = confidence
            && (!confidence.is_finite() || !(0.0..=1.0).contains(&confidence))
        {
            return Err(FindingWireError::InvalidConfidence);
        }
        let rule_id_static = intern_str(rule_id).ok_or(FindingWireError::InterningLimit)?;
        let rule_title_static = intern_str(rule_title).ok_or(FindingWireError::InterningLimit)?;
        let cwe = if cwe.is_empty() {
            None
        } else {
            let owned: Vec<CweRef> = cwe
                .into_iter()
                .map(OwnedCweRef::into_static)
                .collect::<Option<_>>()
                .ok_or(FindingWireError::InterningLimit)?;
            Some(owned.into_boxed_slice())
        };
        let mut finding = Finding::new(FindingInputs::new(
            rule_id_static,
            rule_title_static,
            file,
            location,
            message,
            severity,
            std::borrow::Cow::Owned(cwe.map_or_else(Vec::new, |cwe| cwe.into_vec())),
        ));
        if let Some((end_line, end_column)) = end {
            finding = finding
                .with_end_checked(end_line, end_column)
                .map_err(|_| FindingWireError::InvalidEndLocation)?;
        }
        if let Some((byte_offset, byte_length)) = byte_range {
            finding = finding
                .with_byte_range_checked(byte_offset, byte_length)
                .map_err(|_| FindingWireError::ByteRangeOverflow)?;
        }
        if let Some((start_byte, end_byte, start_line, end_line)) = function_range {
            finding = finding
                .with_function_range_checked(start_byte, end_byte, start_line, end_line)
                .map_err(|_| FindingWireError::InvalidFunctionRange)?;
        }
        if let Some(snippet) = snippet {
            finding = finding.with_snippet(snippet);
        }
        if let Some(fix) = fix {
            finding = finding.with_fix(fix);
        }
        if let Some(evidence) = evidence {
            finding = finding.with_evidence(evidence);
        }
        if let Some(confidence) = confidence {
            finding = finding
                .with_confidence_checked(confidence)
                .map_err(|_| FindingWireError::InvalidConfidence)?;
        }
        if let Some(tags) = tags {
            finding = finding.with_tags(tags);
        }
        if suppressed {
            finding = finding.mark_suppressed();
        }
        if let Some(remediation) = remediation {
            finding = finding.with_remediation(remediation);
        }
        Ok(finding)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::rules::{FindingInputs, LineCol, Severity};

    #[test]
    fn cache_string_interning_has_a_hard_limit() {
        let base = Finding::new(FindingInputs::new(
            "CACHE-BASE",
            "cache base",
            "file.go",
            LineCol::try_new(1, 1).expect("valid location"),
            "message",
            Severity::Info,
            Cow::Owned(Vec::new()),
        ));

        let mut rejected = false;
        for index in 0..=MAX_INTERNED_STRINGS {
            let mut wire = FindingWire::from(base.clone());
            wire.rule_id = format!("CACHE-UNIQUE-ID-{index}");
            wire.rule_title = format!("cache unique title {index}");
            if wire.into_finding().is_err() {
                rejected = true;
                break;
            }
        }

        assert!(rejected, "unique cache strings must eventually be rejected");
    }

    fn valid_wire() -> FindingWire {
        FindingWire::from(Finding::new(FindingInputs::new(
            "CACHE-VALID",
            "cache valid",
            "file.go",
            LineCol::try_new(1, 1).expect("valid location"),
            "message",
            Severity::Info,
            Cow::Owned(Vec::new()),
        )))
    }

    #[test]
    fn rejects_invalid_cache_ranges_and_confidence() {
        let mut wire = valid_wire();
        wire.line = 0;
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.end_line = Some(1);
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.end_line = Some(0);
        wire.end_column = Some(1);
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.byte_offset = Some(1);
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.byte_offset = Some(usize::MAX);
        wire.byte_length = Some(1);
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.function_start_byte = Some(4);
        wire.function_end_byte = Some(2);
        wire.function_start_line = Some(1);
        wire.function_end_line = Some(1);
        assert!(wire.into_finding().is_err());

        let mut wire = valid_wire();
        wire.confidence = Some(f32::NAN);
        assert!(wire.into_finding().is_err());
    }
}

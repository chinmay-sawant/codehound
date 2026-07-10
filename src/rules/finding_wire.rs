//! Wire shape used by the cache when serializing a finding. Mirrors
//! [`Finding`] except `cwe` is owned and `rule_id` / `rule_title` are
//! `String`s. The cache writes this struct and converts back to
//! [`Finding`] on read.
//!
//! Strings are interned (one leak per unique value) so cache churn does
//! not grow RSS unbounded.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::cwe::CweRef;

use super::finding::Finding;
use super::finding_view::FindingView;

/// Intern a string into process-lifetime storage, reusing prior entries.
/// Bounds leak growth to unique strings (rule IDs, titles, CWE names/URLs).
fn intern_str(s: String) -> &'static str {
    static TABLE: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();
    let table = TABLE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match table.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(&existing) = guard.get(&s) {
        return existing;
    }
    let leaked: &'static str = Box::leak(s.clone().into_boxed_str());
    guard.insert(s, leaked);
    leaked
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
    fn into_static(self) -> CweRef {
        CweRef {
            id: self.id,
            name: intern_str(self.name),
            url: intern_str(self.url),
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
        let rule_id_static = intern_str(rule_id);
        let rule_title_static = intern_str(rule_title);
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

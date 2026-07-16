//! Severity levels for findings.
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Finding severity used by failure policy and reporters.
pub enum Severity {
    /// Informational finding that does not normally fail a scan.
    Info,
    /// Low-impact finding.
    Low,
    /// Moderate finding that participates in failure policy.
    Medium,
    /// High-impact finding.
    High,
    /// Critical finding requiring immediate attention.
    Critical,
}

impl Severity {
    /// Return whether this severity participates in the default failure gate.
    pub fn is_failure(self) -> bool {
        matches!(self, Severity::Medium | Severity::High | Severity::Critical)
    }

    /// Return the stable lowercase wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

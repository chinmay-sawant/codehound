//! Static metadata about a rule.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use serde::Serialize;

use super::Severity;
use crate::cwe::CweRef;

/// Description of a detector / rule.
#[derive(Debug, Clone, Serialize)]
pub struct RuleMetadata {
    /// Stable identifier, e.g. `CWE-89`.
    pub id: &'static str,
    /// Short title.
    pub title: &'static str,
    /// Longer description.
    pub description: &'static str,
    /// Default severity.
    pub severity: Severity,
    /// CWE references (can be multiple).
    pub cwe: &'static [CweRef],
    /// Suggested fix or note.
    pub fix: Option<&'static str>,
}
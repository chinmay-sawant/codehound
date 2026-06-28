//! Stable finding identity.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use std::fmt;

use serde::{Deserialize, Serialize};

use super::Finding;

pub const FINGERPRINT_TOOL: &str = "slopguard";
pub const FINGERPRINT_VERSION: u32 = 1;

/// Canonical identity for a finding across output formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint {
    pub tool: String,
    pub version: u32,
    pub rule_id: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
}

impl Fingerprint {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            tool: FINGERPRINT_TOOL.to_string(),
            version: FINGERPRINT_VERSION,
            rule_id: finding.rule_id.to_string(),
            file: finding.file.replace('\\', "/"),
            line: finding.line,
            column: finding.column,
        }
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}",
            FINGERPRINT_TOOL, FINGERPRINT_VERSION, self.rule_id, self.file, self.line, self.column
        )
    }
}

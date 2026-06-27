//! Stable finding identity.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FingerprintParseError {
    #[error("fingerprint must start with {FINGERPRINT_TOOL}:{FINGERPRINT_VERSION}:")]
    InvalidPrefix,
    #[error("fingerprint is missing {0}")]
    MissingField(&'static str),
    #[error("fingerprint has invalid {field}: {value}")]
    InvalidNumber { field: &'static str, value: String },
}

impl Fingerprint {
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            tool: FINGERPRINT_TOOL.to_string(),
            version: FINGERPRINT_VERSION,
            rule_id: finding.rule_id.to_string(),
            file: normalize_file_path(&finding.file),
            line: finding.line,
            column: finding.column,
        }
    }

    #[must_use = "fingerprint parse failures must be handled"]
    pub fn parse(value: &str) -> Result<Self, FingerprintParseError> {
        let prefix = format!("{FINGERPRINT_TOOL}:{FINGERPRINT_VERSION}:");
        let Some(rest) = value.strip_prefix(&prefix) else {
            return Err(FingerprintParseError::InvalidPrefix);
        };

        let (rule_id, location) = rest
            .split_once(':')
            .ok_or(FingerprintParseError::MissingField("rule_id"))?;
        if rule_id.is_empty() {
            return Err(FingerprintParseError::MissingField("rule_id"));
        }

        let mut parts = location.rsplitn(3, ':');
        let column = parts
            .next()
            .ok_or(FingerprintParseError::MissingField("column"))
            .and_then(|s| parse_usize("column", s))?;
        let line = parts
            .next()
            .ok_or(FingerprintParseError::MissingField("line"))
            .and_then(|s| parse_usize("line", s))?;
        let file = parts
            .next()
            .ok_or(FingerprintParseError::MissingField("file"))?;
        if file.is_empty() {
            return Err(FingerprintParseError::MissingField("file"));
        }

        Ok(Self {
            tool: FINGERPRINT_TOOL.to_string(),
            version: FINGERPRINT_VERSION,
            rule_id: rule_id.to_string(),
            file: normalize_file_path(file),
            line,
            column,
        })
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}",
            self.tool, self.version, self.rule_id, self.file, self.line, self.column
        )
    }
}

fn normalize_file_path(file: &str) -> String {
    file.replace('\\', "/")
}

fn parse_usize(field: &'static str, value: &str) -> Result<usize, FingerprintParseError> {
    value
        .parse::<usize>()
        .map_err(|_| FingerprintParseError::InvalidNumber {
            field,
            value: value.to_string(),
        })
}

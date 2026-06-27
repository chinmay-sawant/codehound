//! Newtypes for finding construction.

use std::fmt;

/// Static rule identifier (e.g. `CWE-89`, `PERF-27`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleId(pub &'static str);

impl RuleId {
    /// Wrap a compile-time rule id.
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Borrow the underlying id string.
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl From<&'static str> for RuleId {
    fn from(id: &'static str) -> Self {
        Self::new(id)
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Relative file path for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilePath(pub String);

impl FilePath {
    /// Construct from any string-like path.
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Borrow the path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for FilePath {
    fn from(path: String) -> Self {
        Self(path)
    }
}

impl From<&str> for FilePath {
    fn from(path: &str) -> Self {
        Self(path.to_string())
    }
}

impl fmt::Display for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
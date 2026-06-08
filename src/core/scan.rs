//! Scan configuration: rule filters and exit policy.

use std::collections::HashSet;

use crate::rules::Severity;

/// When the CLI should exit non-zero based on finding severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FailPolicy {
    /// Fail on medium, high, or critical (default).
    #[default]
    MediumAsErrors,
    /// Fail only on high or critical.
    Strict,
    /// Always exit 0 for findings.
    NoFail,
}

impl FailPolicy {
    pub fn should_fail(self, severity: Severity) -> bool {
        match self {
            Self::NoFail => false,
            Self::Strict => matches!(severity, Severity::High | Severity::Critical),
            Self::MediumAsErrors => severity.is_failure(),
        }
    }
}

/// Per-run filters passed to detectors.
#[derive(Debug, Default, Clone)]
pub struct ScanContext {
    pub only: Option<HashSet<String>>,
    pub skip: HashSet<String>,
    pub fail_policy: FailPolicy,
}

impl ScanContext {
    pub fn allows(&self, rule_id: &str) -> bool {
        if self.skip.contains(rule_id) {
            return false;
        }
        if let Some(only) = &self.only {
            return only.contains(rule_id);
        }
        true
    }
}

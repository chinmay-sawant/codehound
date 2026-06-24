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
    pub show_ignored: bool,
    /// When true, detectors collect per-rule timing. Also implies stats collection.
    pub debug_timing: bool,
    /// When true, the run produces a machine-readable diagnostics file.
    /// Also implies stats and phase timing collection.
    pub diagnostics: bool,
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

    /// True if the run should collect scan statistics and phase timings.
    pub fn collect_stats(&self) -> bool {
        self.debug_timing || self.diagnostics
    }

    /// True if the run should collect per-detector timings.
    pub fn collect_detector_timing(&self) -> bool {
        self.debug_timing || self.diagnostics
    }
}

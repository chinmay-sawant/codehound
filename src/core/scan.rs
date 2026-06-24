//! Scan configuration: rule filters and exit policy.

use std::collections::HashSet;

use crate::rules::{Finding, Severity};

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
#[derive(Debug, Clone)]
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
    /// When true, use the experimental taint-tracking engine for the
    /// supported CWE rules (CWE-22/78/89/79).
    pub taint_enabled: bool,
    /// When true, emit taint paths in finding evidence.
    pub taint_show_paths: bool,
    /// When false, suppress all BP-* bad-practice rules.
    pub bad_practices_enabled: bool,
    /// Optional severity override for BP-* bad-practice findings.
    pub bad_practice_severity: Option<Severity>,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            only: None,
            skip: HashSet::new(),
            fail_policy: FailPolicy::default(),
            show_ignored: false,
            debug_timing: false,
            diagnostics: false,
            taint_enabled: false,
            taint_show_paths: false,
            bad_practices_enabled: true,
            bad_practice_severity: None,
        }
    }
}

impl ScanContext {
    pub fn allows(&self, rule_id: &str) -> bool {
        if rule_id.starts_with("BP-") && !self.bad_practices_enabled {
            return false;
        }
        if self.skip.contains(rule_id) {
            return false;
        }
        if self
            .skip
            .iter()
            .any(|pattern| rule_matches(pattern, rule_id))
        {
            return false;
        }
        if let Some(only) = &self.only {
            return only.iter().any(|pattern| rule_matches(pattern, rule_id));
        }
        true
    }

    pub fn apply_finding_overrides(&self, finding: &mut Finding) {
        if finding.rule_id.starts_with("BP-") {
            if let Some(severity) = self.bad_practice_severity {
                finding.severity = severity;
            }
        }
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

fn rule_matches(pattern: &str, rule_id: &str) -> bool {
    if pattern == rule_id {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return rule_id.starts_with(prefix);
    }
    false
}

//! Per-run filters passed to detectors.

use std::collections::HashSet;

use crate::rules::{Finding, Severity};

use super::policy::FailPolicy;

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
    /// When true, print a compact scan summary to stderr.
    pub diagnostics_summary: bool,
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
            diagnostics_summary: false,
            taint_enabled: true,
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
        if self.skip.iter().any(|pattern| {
            pattern == rule_id
                || pattern
                    .strip_suffix('*')
                    .is_some_and(|p| rule_id.starts_with(p))
        }) {
            return false;
        }
        if let Some(only) = &self.only {
            return only.iter().any(|pattern| {
                pattern == rule_id
                    || pattern
                        .strip_suffix('*')
                        .is_some_and(|p| rule_id.starts_with(p))
            });
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

    /// True if the run should collect scan statistics, phase timings, and
    /// per-detector timings.
    pub fn collect_stats(&self) -> bool {
        self.debug_timing || self.diagnostics || self.diagnostics_summary
    }
    // ponytail: collect_detector_timing was identical to collect_stats — merged.
    // Callers migrated to collect_stats().
}

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
    /// Max inter-procedural summary hops (1 = direct caller→callee only).
    /// Higher values enable bounded multi-hop refinement within a package.
    pub taint_max_depth: u32,
    /// When false, suppress all BP-* bad-practice rules.
    pub bad_practices_enabled: bool,
    /// Optional severity override for BP-* bad-practice findings.
    pub bad_practice_severity: Option<Severity>,
    /// Per-rule severity overrides (e.g. BP-1 → High). Applied after the
    /// global BP severity override when present.
    pub severity_overrides: std::collections::HashMap<String, Severity>,
    /// When true, text output includes extra scan stats (bytes, phase timing).
    pub verbose: bool,
    /// When true, retain per-file sources in `AnalysisResult.source_cache`
    /// (needed for `--export-context` / `--export-chunks`). Default CI/JSON/SARIF
    /// paths leave this false to avoid a monorepo RAM tax.
    pub retain_sources: bool,
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
            // Off by default; enable via --taint or [codehound.taint] enabled = true.
            taint_enabled: false,
            taint_show_paths: false,
            taint_max_depth: 1,
            bad_practices_enabled: true,
            bad_practice_severity: None,
            severity_overrides: std::collections::HashMap::new(),
            verbose: false,
            retain_sources: false,
        }
    }
}

impl ScanContext {
    pub fn allows(&self, rule_id: &str) -> bool {
        if rule_id.starts_with("BP-") && !self.bad_practices_enabled {
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
        if let Some(severity) = self.severity_overrides.get(finding.rule_id) {
            finding.severity = *severity;
        }
    }

    /// True if the run should collect scan statistics, phase timings, and
    /// per-detector timings.
    pub fn collect_stats(&self) -> bool {
        self.verbose || self.debug_timing || self.diagnostics || self.diagnostics_summary
    }
    // ponytail: collect_detector_timing was identical to collect_stats — merged.
    // Callers migrated to collect_stats().

    /// Stable hash of settings that change which detectors run / findings
    /// are stored. Used to invalidate the incremental cache when the pack
    /// or filter set changes (e.g. recommended → all).
    pub fn rule_config_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        use std::collections::BTreeSet;

        let mut only: BTreeSet<&str> = BTreeSet::new();
        if let Some(set) = &self.only {
            only.extend(set.iter().map(String::as_str));
        }
        let skip: BTreeSet<&str> = self.skip.iter().map(String::as_str).collect();
        // Hash via a portable string so disk caches are stable across processes.
        let payload = format!(
            "only={only:?}|skip={skip:?}|taint={}|bp={}|depth={}",
            self.taint_enabled, self.bad_practices_enabled, self.taint_max_depth
        );
        let digest = Sha256::digest(payload.as_bytes());
        let hash_str = crate::engine::hex_lower(digest);
        hash_str[..16].to_string()
    }
}

//! Aggregate statistics for a scan run.

use std::collections::HashMap;

use serde::Serialize;

use crate::engine::result::AnalysisResult;
use crate::engine::timing::TimingSummary;

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub files_errored: usize,
    pub bytes_scanned: u64,
    pub lines_scanned: u64,

    pub cache_hits: usize,
    pub cache_misses: usize,

    pub findings_total: usize,
    pub findings_by_severity: HashMap<String, usize>,
    pub findings_by_rule: Vec<(String, usize)>,
    pub findings_suppressed: usize,

    pub rules_executed: usize,
    pub detectors_loaded: usize,

    pub timing: Option<TimingSummary>,
}

impl ScanStats {
    /// Build stats from a finished result. Timing is attached separately
    /// because it is collected while the scan runs.
    pub fn from_result(result: &AnalysisResult) -> Self {
        let mut findings_by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_rule: HashMap<String, usize> = HashMap::new();

        for finding in &result.findings {
            *findings_by_severity
                .entry(finding.severity.as_str().to_string())
                .or_insert(0) += 1;
            *by_rule.entry(finding.rule_id.to_string()).or_insert(0) += 1;
        }

        let mut findings_by_rule: Vec<(String, usize)> = by_rule.into_iter().collect();
        findings_by_rule.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        Self {
            files_scanned: 0,
            files_skipped: 0,
            files_errored: result.errors.len(),
            bytes_scanned: 0,
            lines_scanned: 0,
            cache_hits: 0,
            cache_misses: 0,
            findings_total: result.findings.len(),
            findings_by_severity,
            findings_by_rule,
            findings_suppressed: result.suppressed_count,
            rules_executed: 0,
            detectors_loaded: 0,
            timing: None,
        }
    }

    /// Merge another stats object into this one. Used to aggregate per-file
    /// stats produced by parallel workers.
    pub fn merge(&mut self, other: &ScanStats) {
        self.files_scanned += other.files_scanned;
        self.files_skipped += other.files_skipped;
        self.files_errored += other.files_errored;
        self.bytes_scanned += other.bytes_scanned;
        self.lines_scanned += other.lines_scanned;
        self.cache_hits += other.cache_hits;
        self.cache_misses += other.cache_misses;
        self.findings_total += other.findings_total;
        self.findings_suppressed += other.findings_suppressed;

        for (sev, count) in &other.findings_by_severity {
            *self.findings_by_severity.entry(sev.clone()).or_insert(0) += count;
        }

        let mut by_rule: HashMap<String, usize> = self.findings_by_rule.drain(..).collect();
        for (rule, count) in &other.findings_by_rule {
            *by_rule.entry(rule.clone()).or_insert(0) += count;
        }
        let mut findings_by_rule: Vec<(String, usize)> = by_rule.into_iter().collect();
        findings_by_rule.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        self.findings_by_rule = findings_by_rule;

        self.rules_executed += other.rules_executed;
        // detectors_loaded is a process-level constant; keep the larger value.
        self.detectors_loaded = self.detectors_loaded.max(other.detectors_loaded);
    }

    /// Attach a timing summary after the scan completes.
    pub fn with_timing(mut self, timing: TimingSummary) -> Self {
        self.timing = Some(timing);
        self
    }

    /// Increment counters for a single successfully scanned file.
    pub fn record_file(&mut self, bytes: u64, lines: u64) {
        self.files_scanned += 1;
        self.bytes_scanned += bytes;
        self.lines_scanned += lines;
    }

    /// Record that a file was skipped during collection.
    pub fn record_skipped(&mut self) {
        self.files_skipped += 1;
    }

    /// Record that a file produced an error.
    pub fn record_errored(&mut self) {
        self.files_errored += 1;
    }

    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }
}

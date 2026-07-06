//! Aggregate statistics for a scan run.

use std::collections::HashMap;

use serde::Serialize;

use crate::engine::timing::TimingSummary;
use crate::rules::Finding;

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
    pub findings_suppressed: usize,

    pub rules_executed: usize,
    pub detectors_loaded: usize,

    pub timing: Option<TimingSummary>,
}

impl ScanStats {
    /// Build findings-related stats from a finished result slice.
    pub fn from_findings(findings: &[Finding], suppressed_count: usize) -> Self {
        let mut findings_by_severity: HashMap<String, usize> = HashMap::new();

        for finding in findings {
            *findings_by_severity
                .entry(finding.severity.as_str().to_string())
                .or_insert(0) += 1;
        }

        Self {
            findings_total: findings.len(),
            findings_by_severity,
            findings_suppressed: suppressed_count,
            ..Default::default()
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

    /// Record that a file produced an error.
    pub fn record_errored(&mut self) {
        self.files_errored += 1;
    }
}

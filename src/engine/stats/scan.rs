//! Aggregate statistics for a scan run.

use std::collections::HashMap;

use serde::Serialize;

use crate::engine::timing::TimingSummary;
use crate::rules::Finding;

#[derive(Debug, Default, Clone, Serialize)]
/// Aggregate counters and optional timing data for one scan.
pub struct ScanStats {
    /// Number of files successfully scanned.
    pub files_scanned: usize,
    /// Number of files skipped by filters or cache policy.
    pub files_skipped: usize,
    /// Number of files that produced scan errors.
    pub files_errored: usize,
    /// Total source bytes scanned.
    pub bytes_scanned: u64,
    /// Total source lines scanned.
    pub lines_scanned: u64,

    /// Number of cache hits.
    pub cache_hits: usize,
    /// Number of cache misses.
    pub cache_misses: usize,

    /// Total emitted findings.
    pub findings_total: usize,
    /// Finding counts grouped by severity string.
    pub findings_by_severity: HashMap<String, usize>,
    /// Number of findings suppressed by policy.
    pub findings_suppressed: usize,

    /// Number of rules executed.
    pub rules_executed: usize,
    /// Number of loaded detectors.
    pub detectors_loaded: usize,

    /// Optional phase timing summary.
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

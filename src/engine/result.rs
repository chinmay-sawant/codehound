//! Analysis output container.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;

use crate::engine::ScanStats;
use crate::rules::Finding;

/// A non-fatal error encountered while scanning a single file. The scan
/// continues; this entry is reported so the caller can surface it.
#[derive(Debug, Clone, Error)]
#[error("{}: {message}", path.display())]
pub struct ScanError {
    pub path: PathBuf,
    pub kind: ScanErrorKind,
    pub message: String,
}

/// Coarse error category — used to map to distinct process exit codes
/// (config / I-O / parse / engine-internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanErrorKind {
    /// Failure reading the file or its parent directory.
    Io,
    /// Source bytes were not valid UTF-8.
    Encoding,
    /// Tree-sitter failed to produce a tree.
    Parse,
    /// A detector raised an error during `run`.
    Engine,
}

impl ScanErrorKind {
    /// Maps to the conventional process exit code for this category.
    pub fn exit_code(self) -> u8 {
        match self {
            ScanErrorKind::Io => 3,
            ScanErrorKind::Encoding => 3,
            ScanErrorKind::Parse => 4,
            ScanErrorKind::Engine => 5,
        }
    }
}

/// Accumulates per-chunk [`MergedScan`](crate::engine::walk::MergedScan)
/// results into a single [`AnalysisResult`]. Encapsulates the chunk-merge
/// logic so that adding a new pipeline field touches one file (this one)
/// instead of 3 files across the engine.
///
/// # Locality
///
/// Adding a per-file field to the pipeline:
/// 1. Add the field to [`ScanEntryResult`](crate::engine::walk::scan_entry::ScanEntryResult)
/// 2. Add the field to [`MergedScan`](crate::engine::walk::MergedScan)
/// 3. Wire it in `merge_chunk`
///
/// That's one accumulator method change instead of 8+ edits across 3 files.
#[derive(Debug)]
pub(crate) struct PipelineAccumulator {
    findings: Vec<Finding>,
    errors: Vec<ScanError>,
    source_cache: HashMap<String, Arc<str>>,
    suppressed_count: usize,
    stats: ScanStats,
    scanned_files: std::collections::HashSet<String>,
}

impl PipelineAccumulator {
    /// Start accumulation after file discovery.
    pub fn new(files_skipped: usize) -> Self {
        Self {
            findings: Vec::new(),
            errors: Vec::new(),
            source_cache: HashMap::new(),
            suppressed_count: 0,
            stats: ScanStats {
                files_skipped,
                ..Default::default()
            },
            scanned_files: std::collections::HashSet::new(),
        }
    }

    /// Record a scanned file path (used later for cache pruning).
    pub fn record_scanned(&mut self, path: String) {
        self.scanned_files.insert(path);
    }

    /// Merge a single chunk's [`MergedScan`] into this accumulator.
    /// Merges per-file timing collected by the chunk into `timing`.
    /// Returns the chunk's `rescan_files` for cascade invalidation.
    pub fn merge_chunk(
        &mut self,
        chunk: crate::engine::walk::MergedScan,
        timing: &mut crate::engine::timing::TimingCollector,
    ) -> Vec<(String, bool)> {
        self.findings.extend(chunk.findings);
        self.errors.extend(chunk.errors);
        self.source_cache.extend(chunk.source_cache);
        self.suppressed_count += chunk.suppressed_count;
        self.stats.merge(&chunk.stats);
        timing.merge_owned(chunk.timing);
        chunk.rescan_files
    }

    pub fn scanned_files(&self) -> &std::collections::HashSet<String> {
        &self.scanned_files
    }

    pub fn findings_mut(&mut self) -> &mut Vec<Finding> {
        &mut self.findings
    }

    pub fn errors(&self) -> &[ScanError] {
        &self.errors
    }

    pub fn record_error(&mut self, error: ScanError) {
        self.errors.push(error);
        self.stats.record_errored();
    }

    pub fn take_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.findings)
    }

    pub fn take_errors(&mut self) -> Vec<ScanError> {
        std::mem::take(&mut self.errors)
    }

    pub fn take_source_cache(&mut self) -> HashMap<String, Arc<str>> {
        std::mem::take(&mut self.source_cache)
    }

    pub fn suppressed_count(&self) -> usize {
        self.suppressed_count
    }

    pub fn take_stats(&mut self) -> ScanStats {
        std::mem::take(&mut self.stats)
    }
}

/// Findings (and per-file errors) from a scan run.
#[must_use]
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    /// Findings emitted by enabled detectors after scan policy is applied.
    pub findings: Vec<Finding>,
    /// Non-fatal per-file errors collected during the scan. The scan does
    /// NOT abort on the first error; instead, the caller decides whether
    /// `errors` should fail the run.
    pub errors: Vec<ScanError>,
    /// File path → source text cache populated during the parse step when
    /// [`ScanContext::retain_sources`](crate::core::ScanContext::retain_sources)
    /// is enabled. Export can read from this instead of hitting disk again.
    pub source_cache: HashMap<String, Arc<str>>,
    /// Findings suppressed by baseline filtering.
    pub suppressed_count: usize,
    /// Optional operational scan statistics. Populated when timing/stats
    /// collection is enabled (via `--debug-timing` or `--diagnostics`).
    pub stats: Option<ScanStats>,
}

impl AnalysisResult {
    /// Return findings emitted by the scan after policy filtering.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Return mutable findings for embedders that apply a post-scan policy.
    pub fn findings_mut(&mut self) -> &mut [Finding] {
        &mut self.findings
    }

    /// Return non-fatal per-file errors collected during the scan.
    pub fn errors(&self) -> &[ScanError] {
        &self.errors
    }

    /// Return retained source text keyed by the normalized file path.
    pub fn source_cache(&self) -> &HashMap<String, Arc<str>> {
        &self.source_cache
    }

    /// Return the number of findings suppressed by baseline filtering.
    pub fn suppressed_count(&self) -> usize {
        self.suppressed_count
    }

    /// Return operational scan statistics when collection was enabled.
    pub fn stats(&self) -> Option<&ScanStats> {
        self.stats.as_ref()
    }

    /// Return whether any finding matches the configured failure policy.
    pub fn should_fail(&self, policy: crate::core::FailPolicy) -> bool {
        self.findings.iter().any(|f| policy.should_fail(f.severity))
    }

    /// Return the total number of bytes retained in the source cache.
    pub fn source_cache_bytes(&self) -> usize {
        self.source_cache.values().map(|source| source.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::engine::{ScanError, ScanErrorKind, ScanStats, walk::MergedScan};

    use super::PipelineAccumulator;

    fn make_finding(n: usize) -> crate::rules::Finding {
        // ponytail: test-only leak for &'static str
        let rule_id = Box::leak(format!("CWE-{n}").into_boxed_str());
        let file = Box::leak(format!("f{n}.go").into_boxed_str());
        use std::borrow::Cow;
        crate::rules::Finding::new(crate::rules::FindingInputs::new(
            rule_id,
            "title",
            file,
            crate::rules::LineCol { line: n, column: 1 },
            "msg",
            crate::rules::Severity::High,
            Cow::Borrowed(&[]),
        ))
    }

    fn make_chunk(findings_count: usize, errors_count: usize) -> MergedScan {
        let findings: Vec<_> = (0..findings_count).map(make_finding).collect();
        let mut errors = Vec::new();
        for i in 0..errors_count {
            errors.push(ScanError {
                path: std::path::PathBuf::from(format!("e{i}.go")),
                kind: ScanErrorKind::Io,
                message: format!("error {i}"),
            });
        }
        MergedScan {
            findings,
            errors,
            source_cache: HashMap::from([("f0.go".into(), Arc::from("source0"))]),
            suppressed_count: 0,
            stats: ScanStats::default(),
            rescan_files: vec![("f0.go".into(), true)],
            timing: crate::engine::timing::TimingCollector::new(false),
        }
    }

    #[test]
    fn new_accumulator_starts_empty() {
        let mut acc = PipelineAccumulator::new(5);
        assert!(acc.take_findings().is_empty());
        assert!(acc.take_errors().is_empty());
        assert_eq!(acc.suppressed_count(), 0);
        assert_eq!(acc.scanned_files().len(), 0);
        let stats = acc.take_stats();
        assert_eq!(stats.files_skipped, 5);
    }

    #[test]
    fn merge_chunk_accumulates_findings_and_errors() {
        let mut acc = PipelineAccumulator::new(0);
        let chunk = make_chunk(3, 2);
        let rescan = acc.merge_chunk(
            chunk,
            &mut crate::engine::timing::TimingCollector::new(false),
        );
        assert_eq!(acc.take_findings().len(), 3);
        assert_eq!(acc.take_errors().len(), 2);
        assert_eq!(rescan, vec![("f0.go".into(), true)]);
    }

    #[test]
    fn merge_chunk_accumulates_source_cache() {
        let mut acc = PipelineAccumulator::new(0);
        let chunk = make_chunk(1, 0);
        acc.merge_chunk(
            chunk,
            &mut crate::engine::timing::TimingCollector::new(false),
        );
        let cache = acc.take_source_cache();
        assert_eq!(cache.get("f0.go").map(|s| s.as_ref()), Some("source0"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn multiple_chunks_merge_correctly() {
        let mut acc = PipelineAccumulator::new(0);
        for _ in 0..3 {
            let chunk = make_chunk(2, 1);
            acc.merge_chunk(
                chunk,
                &mut crate::engine::timing::TimingCollector::new(false),
            );
        }
        assert_eq!(acc.take_findings().len(), 6);
        assert_eq!(acc.take_errors().len(), 3);
    }

    #[test]
    fn record_scanned_tracks_file_paths() {
        let mut acc = PipelineAccumulator::new(0);
        acc.record_scanned("a.go".into());
        acc.record_scanned("b.go".into());
        assert_eq!(acc.scanned_files().len(), 2);
        assert!(acc.scanned_files().contains("a.go"));
    }

    #[test]
    fn findings_mut_allows_mutation() {
        let mut acc = PipelineAccumulator::new(0);
        let chunk = make_chunk(1, 0);
        acc.merge_chunk(
            chunk,
            &mut crate::engine::timing::TimingCollector::new(false),
        );
        assert_eq!(acc.findings_mut().len(), 1);
        acc.findings_mut().clear();
        assert!(acc.take_findings().is_empty());
    }
}

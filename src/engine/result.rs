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

impl std::fmt::Display for ScanErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScanErrorKind::Io => "io",
            ScanErrorKind::Encoding => "encoding",
            ScanErrorKind::Parse => "parse",
            ScanErrorKind::Engine => "engine",
        };
        f.write_str(s)
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
    /// Drains the global timing collector into `timing` automatically.
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
        crate::engine::timing::drain_global(timing);
        chunk.rescan_files
    }

    pub fn scanned_files(&self) -> &std::collections::HashSet<String> {
        &self.scanned_files
    }

    pub fn stats(&self) -> &ScanStats {
        &self.stats
    }

    pub fn stats_mut(&mut self) -> &mut ScanStats {
        &mut self.stats
    }

    pub fn findings_mut(&mut self) -> &mut Vec<Finding> {
        &mut self.findings
    }

    pub fn errors(&self) -> &[ScanError] {
        &self.errors
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

/// Builder for [`AnalysisResult`]. Accumulates findings, errors, and
/// stats, then produces a single [`AnalysisResult`] via [`build`](AnalysisResultBuilder::build).
///
/// # Locality
///
/// Adding a new result field requires editing this builder and the
/// `build()` method — one file instead of the scattered field-by-field
/// wiring in `analyze_paths`.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct AnalysisResultBuilder {
    findings: Vec<Finding>,
    errors: Vec<ScanError>,
    source_cache: HashMap<String, Arc<str>>,
    suppressed_count: usize,
    stats: Option<ScanStats>,
}

#[allow(dead_code)]
impl AnalysisResultBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_findings(&mut self, more: &mut Vec<Finding>) {
        self.findings.append(more);
    }

    pub fn add_errors(&mut self, more: &mut Vec<ScanError>) {
        self.errors.append(more);
    }

    pub fn add_source_cache(&mut self, more: HashMap<String, Arc<str>>) {
        self.source_cache.extend(more);
    }

    pub fn add_suppressed(&mut self, count: usize) {
        self.suppressed_count += count;
    }

    pub fn set_stats(&mut self, stats: ScanStats) {
        self.stats = Some(stats);
    }

    /// Consume the builder and produce the final [`AnalysisResult`].
    /// Caller is responsible for sorting and stats finalisation.
    pub fn build(self) -> AnalysisResult {
        AnalysisResult {
            findings: self.findings,
            errors: self.errors,
            source_cache: self.source_cache,
            suppressed_count: self.suppressed_count,
            stats: self.stats,
        }
    }

    pub fn into_findings(mut self) -> Vec<Finding> {
        std::mem::take(&mut self.findings)
    }
}

/// Findings (and per-file errors) from a scan run.
#[must_use]
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    /// Non-fatal per-file errors collected during the scan. The scan does
    /// NOT abort on the first error; instead, the caller decides whether
    /// `errors` should fail the run.
    pub errors: Vec<ScanError>,
    /// File path → source text cache populated during the parse step.
    /// Export (and future passes) can read from this instead of hitting
    /// disk again.
    pub source_cache: HashMap<String, Arc<str>>,
    /// Findings suppressed by baseline filtering.
    pub suppressed_count: usize,
    /// Optional operational scan statistics. Populated when timing/stats
    /// collection is enabled (via `--debug-timing` or `--diagnostics`).
    pub stats: Option<ScanStats>,
}

impl AnalysisResult {
    pub fn should_fail(&self, policy: crate::core::FailPolicy) -> bool {
        self.findings.iter().any(|f| policy.should_fail(f.severity))
    }

    pub fn source_cache_bytes(&self) -> usize {
        self.source_cache.values().map(|source| source.len()).sum()
    }
}

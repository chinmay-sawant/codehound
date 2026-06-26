//! `Analyzer::analyze_paths`: top-level scan orchestration with cache,
//! cascade-invalidation, pruning, and stats aggregation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use crate::engine::{
    SCAN_CHUNK_SIZE,
    cache::CacheStore,
    dependencies::{discover_project_root, go_module_prefix},
    result::AnalysisResult,
    stats::ScanStats,
    timing::TimingCollector,
    walk::{collect_entries, scan_entries_parallel},
};

use super::types::Analyzer;

impl Analyzer {
    /// Run the scan. When `cache` is `Some`, the scan consults the
    /// cache for files whose content hash has not changed, and writes
    /// back new entries for files it scans. The cache is flushed
    /// before this method returns.
    pub fn analyze_paths<I, P>(
        &self,
        paths: I,
        mut cache: Option<&mut CacheStore>,
    ) -> Result<AnalysisResult>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut timing = TimingCollector::new(self.collect_stats);

        // Resolve project_root / module_prefix from the first scan
        // path. `Analyzer::build` provides sensible defaults from
        // the cwd, but a user scanning an external project gets the
        // wrong go.mod otherwise.
        let paths: Vec<PathBuf> = paths
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();
        let project_root = paths
            .first()
            .map(|p| discover_project_root(p))
            .unwrap_or_else(|| self.project_root.clone());
        let module_prefix = go_module_prefix(&project_root).or_else(|| self.module_prefix.clone());

        let (entries, files_skipped) = timing.measure("file_walk", || {
            collect_entries(
                &self.registry,
                paths.iter().map(|p| p.as_path()),
                &self.lang_filter,
                &self.path_filters,
            )
        })?;

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut source_cache: HashMap<String, Arc<str>> = HashMap::new();
        let mut suppressed_count = 0;
        let mut stats = ScanStats::default();
        stats.files_skipped = files_skipped;
        let mut scanned_files: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(entries.len());
        for entry in &entries {
            scanned_files.insert(entry.path.display().to_string());
        }

        for chunk in entries.chunks(SCAN_CHUNK_SIZE) {
            let (
                chunk_findings,
                chunk_errors,
                chunk_source_cache,
                chunk_suppressed_count,
                chunk_stats,
                chunk_timing,
                chunk_rescan_files,
            ) = scan_entries_parallel(
                &self.registry,
                &self.ctx,
                chunk,
                cache.as_deref_mut(),
                &project_root,
                module_prefix.as_deref(),
            )?;
            findings.extend(chunk_findings);
            errors.extend(chunk_errors);
            source_cache.extend(chunk_source_cache);
            suppressed_count += chunk_suppressed_count;
            stats.merge(&chunk_stats);
            timing.merge(&chunk_timing);

            // Transitive invalidation: every file whose content
            // hash changed is, by definition, a dependency of any
            // cache entry that still lists it. Walk the manifest and
            // drop those dependents so the next scan (or a
            // re-lookup) re-parses them. Brand-new entries (no
            // previous hash) are NOT cascaded — there is nothing to
            // invalidate yet.
            if let Some(cache) = cache.as_deref_mut() {
                for (rescanned_file, hash_changed) in chunk_rescan_files {
                    if !hash_changed {
                        continue;
                    }
                    let removed = cache.invalidate_dependent(&rescanned_file);
                    if removed > 0 {
                        tracing::info!(
                            file = %rescanned_file,
                            removed,
                            "cascade-invalidated dependents"
                        );
                    }
                }
            }
        }

        // Prune orphan cache entries (files that were deleted since
        // the last scan). Done at the analyzer level so it still runs
        // when `entries` is empty.
        if let Some(cache) = cache.as_deref_mut() {
            if let Ok(removed) = cache.prune(&scanned_files) {
                if removed > 0 {
                    tracing::debug!(removed, "pruned stale cache entries");
                }
            }
        }

        timing.measure("sort_results", || sort_findings(&mut findings));

        if !errors.is_empty() {
            tracing::warn!(
                error_count = errors.len(),
                "scan completed with per-file errors"
            );
        }

        let mut result = AnalysisResult {
            findings,
            errors,
            source_cache,
            suppressed_count,
            stats: None,
        };

        if self.collect_stats {
            let mut scan_stats = ScanStats::from_result(&result);
            scan_stats.files_scanned = stats.files_scanned;
            scan_stats.files_skipped = stats.files_skipped;
            scan_stats.files_errored = stats.files_errored;
            scan_stats.bytes_scanned = stats.bytes_scanned;
            scan_stats.lines_scanned = stats.lines_scanned;
            scan_stats.rules_executed = stats.rules_executed;
            scan_stats.detectors_loaded = self.registry.detector_count();
            scan_stats.timing = Some(timing.to_summary());
            result.stats = Some(scan_stats);
        }

        if let Some(cache) = cache {
            if let Err(e) = cache.flush() {
                tracing::warn!(error = %e, "failed to flush incremental cache");
            }
        }

        Ok(result)
    }
}

pub(super) fn sort_findings(findings: &mut [crate::rules::Finding]) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
}
